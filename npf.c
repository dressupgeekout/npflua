/*
 * npf.c -- Configure NetBSD's packet filter from a Lua script
 * Christian Koch <cfkoch@sdf.lonestar.org>
 * Jan Danielsson <jan.m.danielsson@gmail.com>
 *
 * TODO
 *  - Does it make sense to avoid needing bit32.bor()? Do we redefine it as
 *  just a set of booleans, all logically ORed together?
 *
 *  - The stats names need to be cleaned up.
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <npf.h>
#include <net/if.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define NPF_DEV_PATH  "/dev/npf"

typedef struct _lnpfconf
{
  int fd;  /* -1 when not in use */
  nl_config_t *conf;
}lnpfconf_t;

typedef struct _lnpfrule
{
  nl_rule_t *rule;
}lnpfrule_t;

typedef struct _lnpfrproc
{
  nl_rproc_t *rproc;
}lnpfrproc_t;

typedef struct _lnpftable
{
  nl_table_t *table;
}lnpftable_t;

int luaopen_npf(lua_State *L);

/*
 * tbl = npf.stats()
 * Return a table containing npf stats
 */
static int
lua_npf_stats(lua_State *L)
{
  int fd;
  static const struct stats_s {
    /* Note: -1 indicates a new section. */
    int		index;
    const char *	name;
  } stats[] = {
    { NPF_STAT_PASS_DEFAULT, "default_pass" },
    { NPF_STAT_PASS_RULESET, "ruleset_pass" },
    { NPF_STAT_PASS_CONN, "state_pass" },
    { NPF_STAT_BLOCK_DEFAULT, "default_block" },
    { NPF_STAT_BLOCK_RULESET, "ruleset_block" },
    { NPF_STAT_CONN_CREATE, "state_allocations" },
    { NPF_STAT_CONN_DESTROY, "state_destructions" },
    { NPF_STAT_NAT_CREATE, "nat_entry_allocations" },
    { NPF_STAT_NAT_DESTROY, "nat_entry_destructions" },
    { NPF_STAT_NBUF_NONCONTIG, "noncontiguous_cases" },
    { NPF_STAT_NBUF_CONTIG_FAIL, "contig_alloc_failures" },
    { NPF_STAT_INVALID_STATE, "cases_in_total" },
    { NPF_STAT_INVALID_STATE_TCP1, "tcp_case_I" },
    { NPF_STAT_INVALID_STATE_TCP2, "tcp_case_II" },
    { NPF_STAT_INVALID_STATE_TCP3, "tcp_case_III" },
    { NPF_STAT_RACE_NAT, "nat_association_race"	},
    { NPF_STAT_RACE_CONN, "duplicate_state_race" },
    { NPF_STAT_FRAGMENTS, "fragments" },
    { NPF_STAT_REASSEMBLY, "reassembled" },
    { NPF_STAT_REASSFAIL, "failed_reassembly" },
    { NPF_STAT_ERROR, "unexpected_errors" }
  };

  if ((fd = open(NPF_DEV_PATH, O_RDONLY)) == -1) {
    luaL_error(L, "open(\"%s\") failed", NPF_DEV_PATH);
  }

  uint64_t *st = calloc(1, NPF_STATS_SIZE);

  if (ioctl(fd, IOC_NPF_STATS, &st) != 0) {
    close(fd);
    free(st);
    luaL_error(L, "ioctl(IOC_NPF_STATS) failed");
  }

  lua_newtable(L);

  for (unsigned i = 0; i < __arraycount(stats); i++) {
    const char *sname = stats[i].name;
    int sidx = stats[i].index;

    lua_pushstring(L, sname);
    lua_pushinteger(L, (lua_Integer)st[sidx]);
    lua_settable(L, -3);
  }

  close(fd);
  free(st);

  return 1;
}

/*
 * conf = npf.config.create()
 */
static int
lua_npf_config_create(lua_State *L)
{
  lnpfconf_t *lconf;

  lconf = lua_newuserdata(L, sizeof(lnpfconf_t));
  lconf->fd = -1;
  lconf->conf = npf_config_create();

  luaL_getmetatable(L, "nl_config_t");
  lua_setmetatable(L, -2);

  return 1;
}

/*
 * Destroy a config context. This needs to handle two cases: Called explicitly
 * or called by the garbage collector.
 */
static int
lua_npf_config_destroy(lua_State *L)
{
  lnpfconf_t *lconf;

  lconf = luaL_checkudata(L, 1, "nl_config_t");

  if(lconf->conf) {
    npf_config_destroy(lconf->conf);
    lconf->conf = NULL;
  }

  if(lconf->fd != -1) {
    if(close(lconf->fd) != -1) {
      luaL_error(L, "close() failed with errno=%d\n", errno);
    }
    lconf->fd = -1;
  }

  return 0;
}

/*
 * status? = npf.config.submit(conf, fd)
 */
static int
lua_npf_config_submit(lua_State *L)
{
  lnpfconf_t *lconf;
  int status;

  lconf = luaL_checkudata(L, 1, "nl_config_t");

  if (lconf->fd == -1) {
    lconf->fd = open(NPF_DEV_PATH, O_RDONLY);
    if (lconf->fd == -1) {
      luaL_error(L, "open(\"%s\") failed", NPF_DEV_PATH);
    }
  }
  status = npf_config_submit(lconf->conf, lconf->fd);

  lua_pushinteger(L, status);
  return 1;
}

/*
 * status? = npf.config.flush(fd)
 */
static int
lua_npf_config_flush(lua_State *L)
{
  lnpfconf_t *lconf;
  int status;

  lconf = luaL_checkudata(L, 1, "nl_config_t");
  if (lconf->fd == -1) {
    lconf->fd = open(NPF_DEV_PATH, O_RDONLY);
    if (lconf->fd == -1) {
      luaL_error(L, "open(\"%s\") failed", NPF_DEV_PATH);
    }
  }

  status = npf_config_flush(lconf->fd);

  lua_pushinteger(L, status);
  return 1;
}

/*
 * rule = npf.rule.create(name, attrs, interface)
 *
 * The name may be nil. The interface is a string, or nil to represent any
 * interface.
 */
static int
lua_npf_rule_create(lua_State *L)
{
  const char *name, *interface;
  uint32_t attrs;
  lnpfrule_t *lrule;

  name = lua_isnil(L, 1) ? NULL : luaL_checkstring(L, 1);
  attrs = (uint32_t)luaL_checkinteger(L, 2);
  interface = lua_isnil(L, 3) ? NULL : luaL_checkstring(L, 3);

  lrule = lua_newuserdata(L, sizeof(lnpfrule_t));
  lrule->rule = npf_rule_create(name, attrs, interface);
  if (lrule->rule == NULL) {
    luaL_error(L, "could not create rule \"%s\"", name);
  }

  luaL_getmetatable(L, "nl_rule_t");
  lua_setmetatable(L, -2);
  return 1;
}

static int
lua_npf_rule_destroy(lua_State *L)
{
  lnpfrule_t *lrule;

  lrule = luaL_checkudata(L, 2, "nl_rule_t");
  if (lrule->rule != NULL) {
    npf_rule_destroy(lrule->rule);
    lrule->rule = NULL;
  }
  return 0;
}

static int
lua_npf_rule_setcode(lua_State *L)
{
  lnpfrule_t *lrule;
  const void *code;
  size_t codelen;
  int type;

  lrule = luaL_checkudata(L, 1, "nl_rule_t");
  type = (int)luaL_checkinteger(L, 2);
  code = luaL_checklstring(L, 3, &codelen);

  npf_rule_setcode(lrule->rule, type, code, codelen);

  return 0;
}

/*
 * bool = npf.rule.exists(conf, name)
 */
static int
lua_npf_rule_exists_p(lua_State *L)
{
  lnpfconf_t *lconf;
  const char *name;

  lconf = luaL_checkudata(L, 1, "nl_config_t");
  name = luaL_checkstring(L, 2);

  lua_pushboolean(L, npf_rule_exists_p(lconf->conf, name));
  return 1;
}

/*
 * status? = npf.rule.insert(conf, parent_rule, rule)
 *
 * parent_rule may be nil.
 */
static int
lua_npf_rule_insert(lua_State *L)
{
  lnpfconf_t *lconf;
  lnpfrule_t *lrule;
  nl_rule_t *parent_rule;
  int status;

  lconf = luaL_checkudata(L, 1, "nl_config_t");
  if(lua_isnil(L, 2)) {
    parent_rule = NULL;
  } else {
    lnpfrule_t *lparent_rule;
    lparent_rule = luaL_checkudata(L, 2, "nl_rule_t");
    parent_rule = lparent_rule->rule;
  }
  lrule = luaL_checkudata(L, 3, "nl_rule_t");

  status = npf_rule_insert(lconf->conf, parent_rule, lrule->rule);

  lua_pushinteger(L, status);
  return 1;
}

/*
 * rproc = npf.rproc.create(name)
 */
static int
lua_npf_rproc_create(lua_State *L)
{
  lnpfrproc_t *lrproc;
  const char *name;

  name = luaL_checkstring(L, 1);

  lrproc = lua_newuserdata(L, sizeof(lnpfrproc_t));

  lrproc->rproc = npf_rproc_create(name);

  if (lrproc->rproc == NULL) {
    luaL_error(L, "could not create rproc \"%s\"", name);
  }

  luaL_getmetatable(L, "nl_rproc_t");
  lua_setmetatable(L, -2);
  return 1;
}

static int
lua_npf_rproc_exists_p(lua_State *L)
{
  return 0;
}

static int
lua_npf_rproc_insert(lua_State *L)
{
  return 0;
}

static int
lua_npf_nat_create(lua_State *L)
{
  return 0;
}

static int
lua_npf_nat_insert(lua_State *L)
{
  return 0;
}

/*
 * table = npf.table_create(name, index, type)
 */
static int
lua_npf_table_create(lua_State *L)
{
  const char *name;
  int type;
  u_int index;
  lnpftable_t *ltable;

  name = lua_isnil(L, 1) ? NULL : (char *)luaL_checkstring(L, 1);
  index = (u_int)luaL_checkinteger(L, 2);
  type = (int)luaL_checkinteger(L, 3);

  ltable = lua_newuserdata(L, sizeof(lnpftable_t));
  ltable->table = npf_table_create(name, index, type);

  if (ltable->table == NULL) {
    luaL_error(L, "could not create table");
  }

  luaL_getmetatable(L, "nl_table_t");
  lua_setmetatable(L, -2);
  return 1;
}

static int
lua_npf_table_destroy(lua_State *L)
{
  lnpftable_t *ltable;

  ltable = luaL_checkudata(L, 1, "nl_table_t");

  if (ltable->table) {
    npf_table_destroy(ltable->table);
    ltable->table = NULL;
  }
  return 0;
}

static int
lua_npf_table_add_entry(lua_State *L)
{
  return 0;
}

/*
 * bool = npf.table_exists(conf, table_id)
 * XXX how to get table_id from a table struct?
 */
static int
lua_npf_table_exists_p(lua_State *L)
{
  return 0;
}

/*
 * status? = npf.table_insert(conf, table)
 */
static int
lua_npf_table_insert(lua_State *L)
{
  lnpfconf_t *lconf;
  lnpftable_t *ltable;
  int status;

  lconf = luaL_checkudata(L, 1, "nl_config_t");
  ltable = luaL_checkudata(L, 2, "nl_table_t");

  status = npf_table_insert(lconf->conf, ltable->table);

  lua_pushinteger(L, status);
  return 1;
}

static int
lua_npf_update_rule(lua_State *L)
{
  return 0;
}

static int
lua_npf_sessions_send(lua_State *L)
{
  return 0;
}

static int
lua_npf_sessions_recv(lua_State *L)
{
  return 0;
}

/* */

const static luaL_Reg npf_conf_funcs[] = {
  {"create", lua_npf_config_create},
  {"destroy", lua_npf_config_destroy},
  {"submit", lua_npf_config_submit},
  {"flush", lua_npf_config_flush},
  {"insert_rule", lua_npf_rule_insert},
  {"rule_exists", lua_npf_rule_exists_p},
  {NULL, NULL}
};

static const struct luaL_Reg conf_m[] = {
  {"submit", lua_npf_config_submit},
  {"flush", lua_npf_config_flush},
  {"destroy", lua_npf_config_destroy},
  {"__gc", lua_npf_config_destroy},
  {NULL, NULL}
};

const static luaL_Reg npf_rule_funcs[] = {
  {"create", lua_npf_rule_create},
  {"destroy", lua_npf_rule_destroy},
  {"setcode", lua_npf_rule_setcode},
  {"exists", lua_npf_rule_exists_p}, /* notice no "_p" */
  {"insert", lua_npf_rule_insert},
  {NULL, NULL}
};

static const struct luaL_Reg rule_m[] = {
  {"destroy", lua_npf_rule_destroy},
  {"setcode", lua_npf_rule_setcode},
  {"__gc", lua_npf_rule_destroy},
  {NULL, NULL}
};

const static luaL_Reg npf_nat_funcs[] = {
  {"create", lua_npf_nat_create},
  {"insert", lua_npf_nat_insert},
  {NULL, NULL}
};

const static luaL_Reg npf_rproc_funcs[] = {
  {"create", lua_npf_rproc_create},
  {"exists", lua_npf_rproc_exists_p}, /* notice no "_p" */
  {"insert", lua_npf_rproc_insert},
  {NULL, NULL}
};

const static luaL_Reg npf_table_funcs[] = {
  {"create", lua_npf_table_create},
  {"destroy", lua_npf_table_destroy},
  {"add_entry", lua_npf_table_add_entry},
  {"exists", lua_npf_table_exists_p}, /* notice no "_p" */
  {"insert", lua_npf_table_insert},
  {NULL, NULL}
};

const static luaL_Reg npf_sessions_funcs[] = {
  {"sessions_send", lua_npf_sessions_send},
  {"sessions_recv", lua_npf_sessions_recv},
  {NULL, NULL}
};

struct constant {
  char *name;
  int value;
};

static struct constant npf_consts[] = {
  {"RULE_PASS", NPF_RULE_PASS},
  {"RULE_FINAL", NPF_RULE_FINAL},
  {"RULE_STATEFUL", NPF_RULE_STATEFUL},
  {"RULE_RETRST", NPF_RULE_RETRST},
  {"RULE_RETICMP", NPF_RULE_RETICMP},
  {"RULE_IN", NPF_RULE_IN},
  {"RULE_OUT", NPF_RULE_OUT},

  {"NATIN", NPF_NATIN},
  {"NATOUT", NPF_NATOUT},
  {"NAT_PORTS", NPF_NAT_PORTS},
  {"NAT_PORTMAP", NPF_NAT_PORTMAP},

  {"AF_INET", AF_INET},
  {"AF_INET6", AF_INET6},

  {"TABLE_HASH", NPF_TABLE_HASH},
  {"TABLE_TREE", NPF_TABLE_TREE},
  {"MAX_TABLE_ID", NPF_MAX_TABLE_ID},

  {NULL, 0}
};

int
luaopen_npf(lua_State *L)
{
  int i;

  luaL_newmetatable(L, "nl_config_t");
  luaL_setfuncs(L, conf_m, 0);
  /* mt.__index = mt -- look in self for missing keys */
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  lua_pop(L, 1);

  luaL_newmetatable(L, "nl_rule_t");
  luaL_setfuncs(L, rule_m, 0);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  lua_pop(L, 1);

  luaL_newmetatable(L, "nl_table_t");
  lua_pop(L, 1);

  luaL_newmetatable(L, "nl_rproc_t");
  lua_pop(L, 1);

  luaL_newmetatable(L, "nl_nat_t");
  lua_pop(L, 1);

  /*
   * Returned "function table" -- this should be the only entry remaining on
   * the stack on return.
   */
  lua_newtable(L);

  lua_pushliteral(L, "stats");
  lua_pushcfunction(L, lua_npf_stats);
  lua_settable(L, -3);

  /*
   * XXX this probably belongs under npf.rule, but I'm not sure what it's meant
   * to do.
   */
  lua_pushliteral(L, "update_rule");
  lua_pushcfunction(L, lua_npf_update_rule);
  lua_settable(L, -3);

  /* npf.config.* */
  lua_pushliteral(L, "config");
  luaL_newlibtable(L, npf_conf_funcs);
  luaL_setfuncs(L, npf_conf_funcs, 0);
  lua_settable(L, -3);

  /* npf.rule.* */
  lua_pushliteral(L, "rule");
  luaL_newlibtable(L, npf_rule_funcs);
  luaL_setfuncs(L, npf_rule_funcs, 0);
  lua_settable(L, -3);

  /* npf.rproc.* */
  lua_pushliteral(L, "rproc");
  luaL_newlibtable(L, npf_rproc_funcs);
  luaL_setfuncs(L, npf_rproc_funcs, 0);
  lua_settable(L, -3);

  /* npf.nat.* */
  lua_pushliteral(L, "nat");
  luaL_newlibtable(L, npf_nat_funcs);
  luaL_setfuncs(L, npf_nat_funcs, 0);
  lua_settable(L, -3);

  /* npf.table.* */
  lua_pushliteral(L, "table");
  luaL_newlibtable(L, npf_table_funcs);
  luaL_setfuncs(L, npf_table_funcs, 0);
  lua_settable(L, -3);

  /* npf.sessions.* */
  lua_pushliteral(L, "sessions");
  luaL_newlibtable(L, npf_sessions_funcs);
  luaL_setfuncs(L, npf_sessions_funcs, 0);
  lua_settable(L, -3);

  i = 0;
  while (npf_consts[i].name != NULL) {
    lua_pushstring(L, npf_consts[i].name);
    lua_pushinteger(L, npf_consts[i].value);
    lua_settable(L, -3);
    i++;
  }

  return 1;
}

/* vim: set ft=c et sw=2 ts=2 sts=2 cinoptions=2 tw=79 :*/
