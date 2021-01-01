#ifndef __PROXY_HADNELR_H
#define __PROXY_HADNELR_H


ssize_t http_proxy_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t http_proxy_show(struct device *dev, struct device_attribute *attr, char *buf);

#endif
