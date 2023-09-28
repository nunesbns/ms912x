// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Red Hat
 */

#include <linux/module.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_damage_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_file.h>
#include <drm/drm_gem_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_managed.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_print.h>
#include <drm/drm_simple_kms_helper.h>
#include <drm/drm_fbdev_generic.h>

#include "ms912x.h"

static int ms912x_usb_suspend(struct usb_interface *interface,
			      pm_message_t message)
{
	struct drm_device *dev = usb_get_intfdata(interface);

	return drm_mode_config_helper_suspend(dev);
}

static int ms912x_usb_resume(struct usb_interface *interface)
{
	struct drm_device *dev = usb_get_intfdata(interface);

	return drm_mode_config_helper_resume(dev);
}

/*
 * FIXME: Dma-buf sharing requires DMA support by the importing device.
 *        This function is a workaround to make USB devices work as well.
 *        See todo.rst for how to fix the issue in the dma-buf framework.
 */
static struct drm_gem_object *
ms912x_driver_gem_prime_import(struct drm_device *dev, struct dma_buf *dma_buf)
{
	struct ms912x_device *ms912x = to_ms912x(dev);

	if (!ms912x->dmadev)
		return ERR_PTR(-ENODEV);

	return drm_gem_prime_import_dev(dev, dma_buf, ms912x->dmadev);
}

DEFINE_DRM_GEM_FOPS(ms912x_driver_fops);

static const struct drm_driver driver = {
	.driver_features = DRIVER_ATOMIC | DRIVER_GEM | DRIVER_MODESET,

	/* GEM hooks */
	.fops = &ms912x_driver_fops,
	DRM_GEM_SHMEM_DRIVER_OPS,
	.gem_prime_import = ms912x_driver_gem_prime_import,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static const struct drm_mode_config_funcs ms912x_mode_config_funcs = {
	.fb_create = drm_gem_fb_create_with_dirty,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};

static const struct ms912x_mode ms912x_mode_list[] = {
	/* Found in captures of the Windows driver */
	MS912X_MODE(800, 600, 60, 0x4200, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1024, 768, 60, 0x4700, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1152, 864, 60, 0x4c00, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1280, 720, 60, 0x4f00, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1280, 800, 60, 0x5700, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1280, 960, 60, 0x5b00, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1280, 1024, 60, 0x6000, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1366, 768, 60, 0x6600, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1400, 1050, 60, 0x6700, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1440, 900, 60, 0x6b00, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1680, 1050, 60, 0x7800, MS912X_PIXFMT_UYVY),
	MS912X_MODE(1920, 1080, 60, 0x8100, MS912X_PIXFMT_UYVY),
};

static const struct ms912x_mode *
ms912x_get_mode(const struct drm_display_mode *mode)
{
	int i;
	int width = mode->hdisplay;
	int height = mode->vdisplay;
int hz = drm_mode_vrefresh(mode);
	for (i = 0; i < ARRAY_SIZE(ms912x_mode_list); i++) {
		if (ms912x_mode_list[i].width == width &&
		    ms912x_mode_list[i].height == height &&
		    ms912x_mode_list[i].hz == hz) {
			return &ms912x_mode_list[i];
		}
	}
	return ERR_PTR(-EINVAL);
}

static void ms912x_pipe_enable(struct drm_simple_display_pipe *pipe,
			       struct drm_crtc_state *crtc_state,
			       struct drm_plane_state *plane_state)
{
	struct ms912x_device *ms912x = to_ms912x(pipe->crtc.dev);
	struct drm_display_mode *mode = &crtc_state->mode;

	ms912x_power_on(ms912x);

	if (crtc_state->mode_changed)
		ms912x_set_resolution(ms912x, ms912x_get_mode(mode));
}

static void ms912x_pipe_disable(struct drm_simple_display_pipe *pipe)
{
	struct ms912x_device *ms912x = to_ms912x(pipe->crtc.dev);

	ms912x_power_off(ms912x);
}

enum drm_mode_status
ms912x_pipe_mode_valid(struct drm_simple_display_pipe *pipe,
		       const struct drm_display_mode *mode)
{
	const struct ms912x_mode *ret = ms912x_get_mode(mode);
	if (IS_ERR(ret)) {
		return MODE_BAD;
	}
	return MODE_OK;
}

int ms912x_pipe_check(struct drm_simple_display_pipe *pipe,
		      struct drm_plane_state *new_plane_state,
		      struct drm_crtc_state *new_crtc_state)
{
	return 0;
}

static struct drm_rect total_damage_rect = { INT_MAX, INT_MAX, INT_MIN,
					     INT_MIN };

static void update_total_damage_rect(const struct drm_rect *new_rect)
{
	total_damage_rect.x1 = min(total_damage_rect.x1, new_rect->x1);
	total_damage_rect.y1 = min(total_damage_rect.y1, new_rect->y1);
	total_damage_rect.x2 = max(total_damage_rect.x2, new_rect->x2);
	total_damage_rect.y2 = max(total_damage_rect.y2, new_rect->y2);
}

static void ms912x_pipe_update(struct drm_simple_display_pipe *pipe,
			       struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = pipe->plane.state;
	struct drm_shadow_plane_state *shadow_plane_state =
		to_drm_shadow_plane_state(state);
	struct drm_rect rect;

	if (drm_atomic_helper_damage_merged(old_state, state, &rect)) {
		update_total_damage_rect(&rect);
		ms912x_fb_send_rect(state->fb, &shadow_plane_state->data[0],
				       &total_damage_rect);
		// Reset the total damage rect after sending
		total_damage_rect =
			(struct drm_rect){ INT_MAX, INT_MAX, INT_MIN, INT_MIN };
	}
}

static const struct drm_simple_display_pipe_funcs ms912x_pipe_funcs = {
	.enable = ms912x_pipe_enable,
	.disable = ms912x_pipe_disable,
	.check = ms912x_pipe_check,
	.mode_valid = ms912x_pipe_mode_valid,
	.update = ms912x_pipe_update,
	DRM_GEM_SIMPLE_DISPLAY_PIPE_SHADOW_PLANE_FUNCS,
};

static const uint32_t ms912x_pipe_formats[] = {
	DRM_FORMAT_XRGB8888,
};

static int ms912x_usb_probe(struct usb_interface *interface,
			    const struct usb_device_id *id)
{
	int ret;
	struct ms912x_device *ms912x;
	struct drm_device *dev;

	ms912x = devm_drm_dev_alloc(&interface->dev, &driver,
				    struct ms912x_device, drm);
	if (IS_ERR(ms912x))
		return PTR_ERR(ms912x);

	ms912x->intf = interface;
	dev = &ms912x->drm;

	init_completion(&ms912x->transfer_done);

	ms912x->dmadev = usb_intf_get_dma_device(interface);
	if (!ms912x->dmadev)
		drm_warn(dev,
			 "buffer sharing not supported"); /* not an error */

	ret = drmm_mode_config_init(dev);
	if (ret)
		goto err_put_device;

	/* No idea */
	dev->mode_config.min_width = 0;
	dev->mode_config.max_width = 10000;
	dev->mode_config.min_height = 0;
	dev->mode_config.max_height = 10000;
	dev->mode_config.funcs = &ms912x_mode_config_funcs;

	ms912x_init_urb(ms912x, 100 * MS912X_MAX_TRANSFER_LENGTH);

	ret = ms912x_connector_init(ms912x);
	if (ret)
		goto err_put_device;

	ret = drm_simple_display_pipe_init(&ms912x->drm, &ms912x->display_pipe,
					   &ms912x_pipe_funcs,
					   ms912x_pipe_formats,
					   ARRAY_SIZE(ms912x_pipe_formats),
					   NULL, &ms912x->connector);
	if (ret)
		goto err_put_device;

	drm_plane_enable_fb_damage_clips(&ms912x->display_pipe.plane);

	drm_mode_config_reset(dev);

	usb_set_intfdata(interface, ms912x);

	drm_kms_helper_poll_init(dev);

	ret = drm_dev_register(dev, 0);
	if (ret)
		goto err_put_device;

	drm_fbdev_generic_setup(dev, 0);

	return 0;

err_put_device:
	put_device(ms912x->dmadev);
	return ret;
}

static void ms912x_usb_disconnect(struct usb_interface *interface)
{
	struct ms912x_device *ms912x = usb_get_intfdata(interface);
	struct drm_device *dev = &ms912x->drm;

	drm_kms_helper_poll_fini(dev);
	drm_dev_unplug(dev);
	drm_atomic_helper_shutdown(dev);
	ms912x_free_urb(ms912x);
	put_device(ms912x->dmadev);
	ms912x->dmadev = NULL;
}

static const struct usb_device_id id_table[] = {
	{ USB_DEVICE_AND_INTERFACE_INFO(0x534d, 0x6021, 0xff, 0x00, 0x00) },
	{ USB_DEVICE_AND_INTERFACE_INFO(0x534d, 0x0821, 0xff, 0x00, 0x00) },
	{},
};
MODULE_DEVICE_TABLE(usb, id_table);

static struct usb_driver ms912x_driver = {
	.name = "ms912x",
	.probe = ms912x_usb_probe,
	.disconnect = ms912x_usb_disconnect,
	.suspend = ms912x_usb_suspend,
	.resume = ms912x_usb_resume,
	.id_table = id_table,
};
module_usb_driver(ms912x_driver);
MODULE_LICENSE("GPL");
