#include <drm/drm_atomic_state_helper.h>
#include <drm/drm_connector.h>
#include <drm/drm_modeset_helper_vtables.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_edid.h>

#include "ms912x.h"

/* Reads the EDID from the device */
static int ms912x_read_edid(void *data, u8 *buf, unsigned int block, size_t len)
{
	struct ms912x_device *ms912x = data;
	int offset = block << 7; // Using bit shift for multiplication by 128 (EDID_LENGTH)
	for (size_t i = 0; i < len; i++) {
		u16 address = 0xc000 + offset + i;
		int byte = ms912x_read_byte(ms912x, address);
		if (byte < 0) {
			return byte; // Return the error code
		}
		buf[i] = byte;
	}
	return 0;
}

/* Gets the supported modes from the device */
static int ms912x_connector_get_modes(struct drm_connector *connector)
{
    struct ms912x_device *ms912x = to_ms912x(connector->dev);
    struct edid *edid = drm_do_get_edid(connector, ms912x_read_edid, ms912x);
    int ret;

    if (!edid) {
        return -ENOMEM;
    }
    drm_connector_update_edid_property(connector, edid);
    ret = drm_add_edid_modes(connector, edid); // Remova a declaração daqui
    kfree(edid);
    return ret;
}


/* Detects the connector status */
static enum drm_connector_status ms912x_detect(struct drm_connector *connector, bool force)
{
	struct ms912x_device *ms912x = to_ms912x(connector->dev);
	int status = ms912x_read_byte(ms912x, 0x32);

	if (status < 0) {
		return connector_status_unknown;
	}

	return status == 1 ? connector_status_connected : connector_status_disconnected;
}

static const struct drm_connector_helper_funcs ms912x_connector_helper_funcs = {
	.get_modes = ms912x_connector_get_modes,
};

static const struct drm_connector_funcs ms912x_connector_funcs = {
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = drm_connector_cleanup,
	.detect = ms912x_detect,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

/* Initializes the connector */
int ms912x_connector_init(struct ms912x_device *ms912x)
{
    int ret;

    drm_connector_helper_add(&ms912x->connector, &ms912x_connector_helper_funcs);
    ret = drm_connector_init(&ms912x->drm, &ms912x->connector, &ms912x_connector_funcs, DRM_MODE_CONNECTOR_HDMIA); // Remova a declaração daqui
    ms912x->connector.polled = DRM_CONNECTOR_POLL_HPD | DRM_CONNECTOR_POLL_CONNECT | DRM_CONNECTOR_POLL_DISCONNECT;
    return ret;
}
