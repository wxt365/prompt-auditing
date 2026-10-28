#ifndef CODEX_GATEWAY_DESKTOP_DARWIN_H
#define CODEX_GATEWAY_DESKTOP_DARWIN_H

int gateway_tray_run(int show_initially);
void gateway_tray_stop(void);
void gateway_desktop_error(const char *message);
int gateway_keychain_key(const char *service, int create, unsigned char *output);

#endif
