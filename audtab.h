// just a dtub for now, will be replaced by bldaudtab
struct audit_table_struct {
  char *key;
  char *path;
  char *file;
  char *stat;
  };
 struct audit_table_struct audit_table[] = {
  { NULL, NULL, NULL, NULL }
 };

char *kernel_version="5.13.0-21-generic";

char aud_text_hash[] = "bb3b60bee23fe4f35c5bcb3d2d7c382f0d5e1038d80ea7a8315cb6cc73522638";

char *audit_table_hash = "539880bf55854120e76b9e56bd6c8c5b3fc17470529b967a097d8d0c22d451bc";
