/*
 * InteMedic (tron) support
 */

// References used...
//   https://www.nuget.org/packages/IC.SlideServices.FileFormat.Tronmedi.NET40/
//   https://github.com/lacchain/openssl-pqe-engine/tree/61d0fe530720f6b7e646db786c79f3db716133f3/ibrand_service

#include "openslide-private.h"
#include "openslide-decode-gsf.h"
#include "openslide-decode-jpeg.h"
#include "openslide-decode-pbkdf2.h"

#include <math.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "json.h"

static const bool SupportLegacy = false; // TODO support Legacy(version <= 3)

static const char TRON_EXT[] = ".tron";
static const char Root[] = "*root*";
static const char MetadataFileName[] = ".tron";

static const char CypherKey[] = "7D4D665B98FB4C6BA7F820A77BF53DA677E28AAA3C8147A4863EAC0042A9713A2D7FF16AEE2F4602A1908948196CB78659B1FCB3A6E14CDA839E2617AC44694B";

static const char SlideMetadata[] = "SlideMetadata";
static const char KEY_MINIMUM_LOD_LEVEL[] = "MinimumLODLevel";
static const char KEY_MAXIMUM_LOD_LEVEL[] = "MaximumLODLevel";
static const char KEY_MAXIMUM_ZOOM_LEVEL[] = "MaximumZoomLevel";
static const char KEY_BACKGROUND_COLOR[] = "BackgroundColor";
static const char KEY_HORIZONTAL_TILE_COUNT[] = "HorizontalTileCount";
static const char KEY_VERTICAL_TILE_COUNT[] = "VerticalTileCount";
static const char KEY_TILE_SIZE[] = "TileSize";
static const char KEY_HORIZONTAL_RESOLUTION[] = "HorizontalResolution";
static const char KEY_VERTICAL_RESOLUTION[] = "VerticalResolution";
static const char KEY_ADDITIONAL_DATA[] = "AdditionalData";
static const char KEY_SCAN_DATE_UTC[] = "ScanDateUtc";
static const char KEY_SCAN_TIME[] = "ScanTime";
static const char KEY_RESAMPLE_FACTOR[] = "ResampleFactor";
static const char KEY_SCANNER_MODEL[] = "ScannerModel";

static const char LabelFileName[] = "label";
static const char MacroFileName[] = "macro";
static const char SampleFileName[] = "sample";
static const char BlankFileName[] = "blank";

struct intemedic_ops_data {
  char *filename;
};

struct image {
  uint64_t uncompressed_size;
  GsfInput *input;
  int32_t imageno; // used only for cache lookup
  int32_t width;
  int32_t height;
  int refcount;
};

struct tile {
  struct image *image;
};

struct level {
  struct _openslide_level base;
  struct _openslide_grid *grid;
};

static void destroy_level(struct level *l) {
  _openslide_grid_destroy(l->grid);
  g_free(l);
}

typedef struct level level;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(level, destroy_level)

static void destroy(openslide_t *osr) {
  struct intemedic_ops_data *data = osr->data;

  // levels
  for (int32_t i = 0; i < osr->level_count; i++) {
    destroy_level((struct level *)osr->levels[i]);
  }
  g_free(osr->levels);

  // the ops data
  g_free(data->filename);
  g_free(data);
}

static void image_unref(struct image *image) {
  if (!--image->refcount) {
    g_object_unref(image->input);
    g_free(image);
  }
}

typedef struct image image;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(image, image_unref)

static void tile_free(gpointer data) {
  struct tile *tile = data;
  image_unref(tile->image);
  g_free(tile);
}

static void insert_tile(struct level *l,
                        struct image *image,
                        double pos_x, double pos_y,
                        int tile_x, int tile_y,
                        int tile_w, int tile_h,
                        int zoom_level) {
  // increment image refcount
  image->refcount++;

  // generate tile
  struct tile *tile = g_new0(struct tile, 1);
  tile->image = image;

  // compute offset
  double offset_x = pos_x - (tile_x * l->base.tile_w);
  double offset_y = pos_y - (tile_y * l->base.tile_h);

  // insert
  _openslide_grid_tilemap_add_tile(l->grid,
                                   tile_x, tile_y,
                                   offset_x, offset_y,
                                   tile_w, tile_h,
                                   tile);

  if (!true) {
    g_debug("zoom %d, tile %d %d, pos %.10g %.10g, offset %.10g %.10g",
            zoom_level, tile_x, tile_y, pos_x, pos_y, offset_x, offset_y);
  }
}

static bool process_local_files(GsfInput *input,
                                int zoom_levels,
                                int32_t *image_number,
                                struct level **levels,
                                GError **err) {
  if (strcmp(input->name, MetadataFileName) == 0 ||
      strcmp(input->name, LabelFileName) == 0 ||
      strcmp(input->name, MacroFileName) == 0 ||
      strcmp(input->name, SampleFileName) == 0 ||
      strcmp(input->name, BlankFileName) == 0)
    return false;

  char *tiledatafilename = input->name;

  uint16_t filenameLength = strlen(tiledatafilename);

  int32_t tile_col = 0;
  int32_t tile_row = 0;
  int32_t zoom_level = 0;

  // spilt filename
  char filename[filenameLength + 1];
  strcpy(filename, tiledatafilename);
  char *temp = strtok(filename, "\\");
  int j = 0;

  while (temp) {
    if (j == 0) {
      sscanf(temp, "%d", &zoom_level);
    } else if (j == 2) {
      sscanf(temp, "%d", &tile_row);
    } else if (j == 3) {
      temp = strtok(temp, ".");
      sscanf(temp, "%d", &tile_col);
    }
    temp = strtok(NULL, "\\");
    j++;
  }

  if (zoom_level < 0) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "zoom level < 0");
    return false;
  } else if (zoom_level >= zoom_levels) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "zoom level >= zoom levels");
    return false;
  }

  struct level *l = levels[zoom_level];
  int64_t tile_w = l->base.tile_w;
  int64_t tile_h = l->base.tile_h;

  // position in this level
  int32_t pos_x = tile_w * tile_col;
  int32_t pos_y = tile_h * tile_row;

  // populate the image structure
  g_autoptr(image) image = g_new0(struct image, 1);
  g_object_ref(input);
  image->input = input;
  image->uncompressed_size = input->size;
  image->imageno = (*image_number)++;
  image->refcount = 1;
  image->width = tile_w;
  image->height = tile_h;

  // start processing 1 image into 1 tile
  // increments image refcount
  insert_tile(l, image,
              pos_x, pos_y,
              pos_x / l->base.tile_w,
              pos_y / l->base.tile_h,
              tile_w, tile_h,
              zoom_level);

  return true;
}

static void ls_R(GsfInput *input,
                 char const *prefix,
                 openslide_t *osr,
                 const char *filename,
                 GError **err,
                 bool build_up_tiles,
                 int zoom_levels,
                 int32_t *image_number,
                 struct level **levels) {
	char const *name = gsf_input_name (input);
	GsfInfile *infile = GSF_IS_INFILE (input) ? GSF_INFILE (input) : NULL;
	gboolean is_dir = infile && gsf_infile_num_children (infile) > 0;
	char *full_name;
	char *new_prefix;
	GDateTime *modtime = gsf_input_get_modtime (input);
	char *modtxt;

	if (prefix) {
		char *display_name = name ?
			g_filename_display_name (name)
			: g_strdup ("?");
		full_name = g_strconcat (prefix,
					 display_name,
					 NULL);
		new_prefix = g_strconcat (full_name, "/", NULL);
		g_free (display_name);
	} else {
		full_name = g_strdup ("*root*");
		new_prefix = g_strdup ("");
	}

	modtxt = modtime
		? g_date_time_format (modtime, "%F %H:%M:%S")
		: g_strdup ("                   ");

  if (strcmp(full_name, MetadataFileName) == 0){
    if (!build_up_tiles) {
      // add properties
      int64_t uncompressed_size = input->size;
      const void* uncompressed = gsf_input_read(input, uncompressed_size, NULL);
      // read header
      uint8_t header[4];
      memcpy(header, uncompressed, 4);
      // Check TRON header
      if (header[0] != 'T' || header[1] != 'R' || header[2] != 'O' || header[3] != 'N') {
        g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                    "Unsupported file: %c%c%c%c", header[0], header[1], header[2], header[3]);
        return;
      }

      uint8_t *slideMetadata = (uint8_t *)uncompressed;
      uint32_t version = (uint32_t)(slideMetadata[4] | (slideMetadata[5] << 8) | (slideMetadata[6] << 16) | (slideMetadata[7] << 24));
      // support version 4 only, for now
      if (!SupportLegacy && version <= 3) {
        g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                    "Unsupported file version: %d", version);
        return;
      }

      // deserialize body
      uint8_t first[32];
      for (int i = 8; i < 40; i++)
        first[i - 8] = slideMetadata[i];

      int blockSize = 128;
      int num = blockSize / 8;

      int dataLength = uncompressed_size - 40;
      uint8_t data[dataLength];
      for (int64_t i = 40; i < uncompressed_size; i++)
        data[i - 40] = slideMetadata[i];

      uint8_t salt[num];
      for (int i = 0; i < num; i++)
        salt[i] = data[i];

      uint8_t iv[num];
      for (int i = num; i < num * 2; i++)
        iv[i - num] = data[i];

      uint8_t input[dataLength - num * 2];
      for (int i = num * 2; i < dataLength; i++)
        input[i - num * 2] = data[i];

      tRfc2898DeriveBytes *rfc2898DeriveBytes = _openslide_Rfc2898DeriveBytes_Init((const unsigned char *)CypherKey, (uint32_t)strlen(CypherKey), salt, num);
      uint8_t *keyBytes = _openslide_Rfc2898DeriveBytes_GetBytes(rfc2898DeriveBytes, 32);
      g_free(rfc2898DeriveBytes);
      int cipherLen = sizeof(input);

      uint8_t output[cipherLen];
      for (int i = 0; i < cipherLen; i++)
        output[i] = 0;
      int outLen1 = 0; int outLen2 = 0;

      EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
      EVP_CIPHER_CTX_init(ctx);
      EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyBytes, iv);
      EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
      EVP_DecryptUpdate(ctx, output, &outLen1, input, cipherLen);
      EVP_DecryptFinal(ctx, output + outLen1, &outLen2);
      EVP_CIPHER_CTX_free(ctx);

      g_free(keyBytes);

      // hash check
      uint8_t second[SHA256_DIGEST_LENGTH];
      for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        second[i] = 0;
      EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
      const EVP_MD *md = EVP_sha256();
      int clearLen = outLen1 + outLen2;
      g_assert(cipherLen == (clearLen + 16 - (clearLen % 16)));
      EVP_DigestInit_ex(mdctx, md, NULL); // ex or ex2
      EVP_DigestUpdate(mdctx, output, clearLen);
      EVP_DigestFinal_ex(mdctx, second, 0);
      EVP_MD_CTX_destroy(mdctx);

      if (strncmp((const char *)first, (const char *)second, SHA256_DIGEST_LENGTH) != 0) {
        g_prefix_error(err, "hash mismatch: ");
        return;
      }

      json_object *slideMetadataJson = json_tokener_parse((const char *)output);
      json_object *slideMetadataObj = json_object_object_get(slideMetadataJson, SlideMetadata);

      json_object_object_foreach(slideMetadataObj, key, val) {
        const char *value = json_object_to_json_string(val);
        if (strcmp(key, KEY_MINIMUM_LOD_LEVEL) == 0 || strcmp(key, KEY_MAXIMUM_LOD_LEVEL) == 0 || strcmp(key, KEY_MAXIMUM_ZOOM_LEVEL) == 0 ||
            strcmp(key, KEY_HORIZONTAL_TILE_COUNT) == 0 || strcmp(key, KEY_VERTICAL_TILE_COUNT) == 0 ||
            strcmp(key, KEY_HORIZONTAL_RESOLUTION) == 0 || strcmp(key, KEY_VERTICAL_RESOLUTION) == 0) {
          g_hash_table_insert(osr->properties,
                              g_strdup_printf("intemedic.%s", key),
                              g_strdup(value));
        } else if (strcmp(key, KEY_BACKGROUND_COLOR) == 0) {
          char bg_value[strlen(value) + 1];
          strcpy(bg_value, value);
          char *temp = strtok(bg_value, ",");
          uint8_t r;
          uint8_t g;
          uint8_t b;
          int j = 0;
          while (temp) {
            if (j == 0) {
              sscanf(temp + 1, "%hhu", &r);
            } else if (j == 1) {
              sscanf(temp, "%hhu", &g);
              temp = strtok(temp, ",");
              sscanf(temp, "%hhu", &b);
            }
            temp = strtok(NULL, "\\");
            j++;
          }
          int64_t bg = (r << 16) | (g << 8) | b;
          g_hash_table_insert(osr->properties,
                              g_strdup_printf("intemedic.%s", key),
                              g_strdup_printf("%" PRId64, bg));
        } else if (strcmp(key, KEY_TILE_SIZE) == 0) {
          char ts_value[strlen(value) + 1];
          strcpy(ts_value, value);
          char *token = strtok(ts_value, ",");
          int32_t tile_size = 0;
          if (token != NULL) {
            sscanf(token + 1, "%d", &tile_size);
            g_hash_table_insert(osr->properties,
                                g_strdup_printf("intemedic.%s", key),
                                g_strdup(token + 1));
          }
        } else if (strcmp(key, KEY_ADDITIONAL_DATA) == 0) {
          json_object_object_foreach(val, key1, val1) {
            const char *value1 = json_object_to_json_string(val1);
            if (strcmp(key1, KEY_SCAN_DATE_UTC) == 0 ||
                strcmp(key1, KEY_SCAN_TIME) == 0 ||
                strcmp(key, KEY_RESAMPLE_FACTOR) == 0 ||
                strcmp(key1, KEY_SCANNER_MODEL) == 0) {
              g_hash_table_insert(osr->properties,
                                  g_strdup_printf("intemedic.%s", key1),
                                  g_strdup(value1));
            }
          }
        }
      }

      json_object_put(slideMetadataJson);
    }
  } else if (strcmp(full_name, LabelFileName) == 0 ||
             strcmp(full_name, MacroFileName) == 0) {
    if (!build_up_tiles){
      const char *associated_image_name = strcmp(full_name, LabelFileName) == 0 ? "label" : "macro";
      if (!_openslide_jpeg_add_associated_image_2(osr, associated_image_name, filename, gsf_input_read(input, input->size, NULL), gsf_input_size(input), err)) {
        g_prefix_error(err, "Couldn't read associated image: %s", associated_image_name);
        return;
      }
    }
  } else if (strcmp(full_name, SampleFileName) != 0 && strcmp(full_name, BlankFileName) != 0 && strcmp(full_name, Root) != 0){
    if (build_up_tiles)
      if (!process_local_files(input, zoom_levels, image_number, levels, err))
        return;
  }

	g_free (modtxt);

	if (is_dir) {
		int i;
		for (i = 0 ; i < gsf_infile_num_children (infile) ; i++) {
			GsfInput *child = gsf_infile_child_by_index (infile, i);
			/* We can get NULL here in case of file corruption.  */
			if (child) {
				ls_R (child, new_prefix, osr, filename, err, build_up_tiles, zoom_levels, image_number, levels);
        g_object_unref (child);
			}
		}
	}

	g_free (full_name);
	g_free (new_prefix);
}

static uint32_t *read_image(openslide_t *osr,
                            struct image *image,
                            int w, int h,
                            GError **err) {
  struct intemedic_ops_data *data = osr->data;
  bool result = false;

  g_autoptr(_openslide_file) f = _openslide_fopen(data->filename, err);
  if (f == NULL) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED, "File is NULL");
    return NULL;
  }
  const void *uncompressed = gsf_input_read(image->input, image->uncompressed_size, NULL);
  if (!uncompressed) {
    g_prefix_error(err, "Error decompressing tile buffer: ");
    return NULL;
  }

  g_autofree uint32_t *dest = g_malloc(w * h * 4);
  result = _openslide_jpeg_decode_buffer(uncompressed,
                                         image->uncompressed_size,
                                         dest, w, h,
                                         err);
  if (!result) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "Couldn't decode jpeg buffer");
    return NULL;
  }
  return g_steal_pointer(&dest);
}

static bool read_missing_tile(openslide_t *osr,
                              cairo_t *cr,
                              struct _openslide_level *level,
                              void *arg G_GNUC_UNUSED,
                              GError **err G_GNUC_UNUSED) {
  bool success = true;

  struct level *l = (struct level *)level;
  int64_t tile_w = l->base.tile_w;
  int64_t tile_h = l->base.tile_h;

  uint8_t bg_r = 0xFF;
  uint8_t bg_g = 0xFF;
  uint8_t bg_b = 0xFF;
  const char *bgcolor = openslide_get_property_value(osr, OPENSLIDE_PROPERTY_NAME_BACKGROUND_COLOR);
  if (bgcolor) {
    uint64_t bg;
    _openslide_parse_uint64(bgcolor, &bg, 16);
    bg_r = (bg >> 16) & 0xFF;
    bg_g = (bg >> 8) & 0xFF;
    bg_b = bg & 0xFF;
  }

  // draw background
  double r = bg_r / 255.0;
  double g = bg_g / 255.0;
  double b = bg_b / 255.0;
  cairo_set_source_rgb(cr, r, g, b);
  cairo_rectangle(cr, 0, 0, tile_w, tile_h);
  cairo_fill(cr);

  return success;
}

static bool read_tile(openslide_t *osr,
                      cairo_t *cr,
                      struct _openslide_level *level,
                      int64_t tile_col G_GNUC_UNUSED,
                      int64_t tile_row G_GNUC_UNUSED,
                      void *data,
                      void *arg G_GNUC_UNUSED,
                      GError **err) {
  struct tile *tile = data;
  bool success = true;

  int iw = tile->image->width;
  int ih = tile->image->height;

  // cache
  g_autoptr(_openslide_cache_entry) cache_entry = NULL;
  uint32_t *tiledata = _openslide_cache_get(osr->cache,
                                            level,
                                            tile->image->imageno,
                                            0,
                                            &cache_entry);

  if (!tiledata) {
    tiledata = read_image(osr, tile->image, iw, ih, err);
    if (tiledata == NULL) {
      return false;
    }
    _openslide_cache_put(osr->cache,
                         level, tile->image->imageno, 0,
                         tiledata,
                         iw * ih * 4,
                         &cache_entry);
  }

  // draw it
  g_autoptr(cairo_surface_t) surface =
      cairo_image_surface_create_for_data((unsigned char *)tiledata,
                                          CAIRO_FORMAT_RGB24,
                                          iw, ih, iw * 4);
  cairo_set_source_surface(cr, surface, 0, 0);
  cairo_paint(cr);

  return success;
}

static bool paint_region(openslide_t *osr G_GNUC_UNUSED, cairo_t *cr,
                         int64_t x, int64_t y,
                         struct _openslide_level *level,
                         int32_t w, int32_t h,
                         GError **err) {
  struct level *l = (struct level *)level;

  return _openslide_grid_paint_region(l->grid, cr, NULL,
                                      x / level->downsample,
                                      y / level->downsample,
                                      level, w, h,
                                      err);
}

static const struct _openslide_ops intemedic_ops = {
    .paint_region = paint_region,
    .destroy = destroy,
};

static bool intemedic_tron_detect(const char *filename G_GNUC_UNUSED,
                                  struct _openslide_tifflike *tl,
                                  GError **err) {
  // reject TIFFs
  if (tl) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "Is a TIFF file");
    return false;
  }

  // verify filename
  if (!g_str_has_suffix(filename, TRON_EXT)) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "File does not have %s extension", TRON_EXT);
    return false;
  }

  // verify existence
  GError *tmp_err = NULL;
  if (!_openslide_fexists(filename, &tmp_err)) {
    if (tmp_err != NULL) {
      g_propagate_prefixed_error(err, tmp_err, "Testing whether file exists: ");
    } else {
      g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                  "File does not exist");
    }
    return false;
  }

  return true;
}

static bool intemedic_tron_open(openslide_t *osr, const char *filename,
                                struct _openslide_tifflike *tl G_GNUC_UNUSED,
                                struct _openslide_hash *quickhash1 G_GNUC_UNUSED, GError **err) {
  g_autoptr(_openslide_file) f = _openslide_fopen(filename, err);
  if (!f) {
    return false;
  }

  GsfInfile *infile = _openslide_gsf_open_archive(filename);
  if (!infile)
    return false;

  // read zip archive
  ls_R(GSF_INPUT(infile), NULL, osr, filename, err, false, 0, 0, 0);
  // g_object_unref(infile);

  char *tiles_across_str = g_hash_table_lookup(osr->properties, "intemedic.HorizontalTileCount");
  char *tiles_down_str = g_hash_table_lookup(osr->properties, "intemedic.VerticalTileCount");
  int64_t tiles_across;
  int64_t tiles_down;
  if (!_openslide_parse_int64(tiles_across_str, &tiles_across)) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "Invalid HorizontalTileCount");
    return false;
  }
  if (!_openslide_parse_int64(tiles_down_str, &tiles_down)) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "Invalid VerticalTileCount");
    return false;
  }

  char *tile_size_str = g_hash_table_lookup(osr->properties, "intemedic.TileSize");
  int64_t tile_size;
  if (!_openslide_parse_int64(tile_size_str, &tile_size)) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "Invalid TileSize");
    return false;
  }

  // calculate base dimensions
  int64_t base_h = tiles_down * tile_size;
  int64_t base_w = tiles_across * tile_size;

  char *MinimumLODLevel_str = g_hash_table_lookup(osr->properties, "intemedic.MinimumLODLevel");
  char *MaximumLODLevel_str = g_hash_table_lookup(osr->properties, "intemedic.MaximumLODLevel");
  int64_t MinimumLODLevel = 0;
  int64_t MaximumLODLevel = 0;
  if (!_openslide_parse_int64(MinimumLODLevel_str, &MinimumLODLevel)) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "Invalid MinimumLODLevel");
    return false;
  }
  if (!_openslide_parse_int64(MaximumLODLevel_str, &MaximumLODLevel)) {
    g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                "Invalid MaximumLODLevel");
    return false;
  }
  // calculate level count
  int32_t zoom_levels = (MaximumLODLevel - MinimumLODLevel) + 1;

  // add properties
  char *bg_str = g_hash_table_lookup(osr->properties, "intemedic.BackgroundColor");
  int64_t bg;
  uint8_t r;
  uint8_t g;
  uint8_t b;
  if (_openslide_parse_int64(bg_str, &bg)) {
    r = (bg >> 16) & 0xFF;
    g = (bg >> 8) & 0xFF;
    b = bg & 0xFF;
    _openslide_set_background_color_prop(osr,
                                         r,
                                         g,
                                         b);
  }

  // set MPP and objective power
  _openslide_duplicate_double_prop(osr, "intemedic.MaximumZoomLevel",
                                   OPENSLIDE_PROPERTY_NAME_OBJECTIVE_POWER);
  _openslide_duplicate_double_prop(osr, "intemedic.HorizontalResolution",
                                   OPENSLIDE_PROPERTY_NAME_MPP_X);
  _openslide_duplicate_double_prop(osr, "intemedic.VerticalResolution",
                                   OPENSLIDE_PROPERTY_NAME_MPP_Y);

  // set up level dimensions and such
  g_autoptr(GPtrArray) level_array =
      g_ptr_array_new_with_free_func((GDestroyNotify)destroy_level);
  int64_t downsample = 1;
  for (int i = 0; i < zoom_levels; i++) {
    // ensure downsample is > 0 and a power of 2
    if (downsample <= 0 || (downsample & (downsample - 1))) {
      g_set_error(err, OPENSLIDE_ERROR, OPENSLIDE_ERROR_FAILED,
                  "Invalid downsample %" PRId64, downsample);
      return false;
    }

    if (i == 0)
      downsample = 1;
    else
      downsample *= 2;

    struct level *l = g_new0(struct level, 1);
    g_ptr_array_add(level_array, l);

    l->base.downsample = downsample;
    l->base.tile_w = (double)tile_size;
    l->base.tile_h = (double)tile_size;

    l->base.w = base_w / l->base.downsample;
    if (l->base.w == 0)
      l->base.w = 1;
    l->base.h = base_h / l->base.downsample;
    if (l->base.h == 0)
      l->base.h = 1;

    l->grid = _openslide_grid_create_tilemap_2(osr,
                                               tile_size,
                                               tile_size,
                                               read_tile, read_missing_tile, tile_free);
  }

  // build up the tiles
  int32_t image_number = 0;
  ls_R(GSF_INPUT(infile), NULL, osr, filename, err, true, zoom_levels, &image_number, (struct level **)level_array->pdata);
  g_object_unref(infile);

  // build ops data
  struct intemedic_ops_data *data = g_new0(struct intemedic_ops_data, 1);
  data->filename = g_strdup(filename);

  // store osr data
  g_assert(osr->data == NULL);
  g_assert(osr->levels == NULL);
  osr->level_count = zoom_levels;
  osr->levels = (struct _openslide_level **)
      g_ptr_array_free(g_steal_pointer(&level_array), false);
  osr->data = data;
  osr->ops = &intemedic_ops;

  return true;
}

const struct _openslide_format _openslide_format_intemedic = {
    .name = "intemedic-tron",
    .vendor = "intemedic",
    .detect = intemedic_tron_detect,
    .open = intemedic_tron_open,
};
