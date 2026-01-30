

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <time.h>

#define DB_NAME "database.db"
#define DB_QUERY "INSERT INTO tab VALUES (null, 'value')"
#define OP_NUM 60000
#define VERIFY_Q 0

static long global_cnt = 1;
extern int main_sqlite(int argc, char *argv[]);

int callback(void *NotUsed, int argc, char **argv, char **azColName);
int sqlite3_insert(int argc, char **argv);

int main_lambda(int argc, char *argv[]) {
  int rc = 0;
  
  if (argc > 1 && strcmp(argv[1], "benchmark") == 0) {
    printf("Inserting %d tuples...\n", OP_NUM);
    rc = sqlite3_insert(argc, argv);
  }else{
    char *argv2[] = {"unikernel"};
    rc = main_sqlite(1, argv2);
  }
  return rc;
}

int callback(void *NotUsed, int argc, char **argv, char **azColName) {
#ifdef VERIFY_Q
  for (int i = 0; i < argc; i++) {
    if (global_cnt % 100 == 0) {
      printf("-> %s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
  }
  global_cnt++;
#endif
  return 0;
}

int sqlite3_insert(int argc, char **argv) {
  sqlite3 *db;
  char *zErrMsg = 0;
  int rc;

  // trace_SQLITE_exec_beg();
  // trace_SQLITE_dbopen_beg();
  rc = sqlite3_open(DB_NAME, &db);
  if (rc) {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return (1);
  }
  // trace_SQLITE_dbopen_end();

  rc = sqlite3_exec(db, "DROP TABLE IF EXISTS tab;", callback, 0, &zErrMsg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  }
  rc = sqlite3_exec(db,
                    "CREATE TABLE tab (contact_id INTEGER PRIMARY KEY, "
                    "first_name TEXT NOT NULL);",
                    callback, 0, &zErrMsg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  }
  for (int i = 0; i < OP_NUM; i++) {
    rc = sqlite3_exec(db, DB_QUERY, callback, 0, &zErrMsg);

    if (rc != SQLITE_OK) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      // trace_SQLITE_ERR();
      sqlite3_free(zErrMsg);
      break;
    }
  }
  // trace_SQLITE_exec_end();

#if VERIFY_Q
  rc = sqlite3_exec(db, "SELECT * FROM tab", callback, 0, &zErrMsg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  }
#endif

  sqlite3_close(db);
  return 0;
}