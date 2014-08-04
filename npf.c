/*
 * npf.c -- Configure NetBSD's packet filter from a Lua script
 * Christian Koch <cfkoch@sdf.lonestar.org>
 *
 * TODO
 *  - I think it would be more idiomatic to add furter namespaces, e.g.
 *  npf.rule.create() instead of npf.rule_create().
 *
 *  - Does it make sense to avoid needing bit32.bor()? Do we redefine it as
 *  just a set of booleans, all logically ORed together?
 */

#include <string.h>

#include <npf.h>
#include <net/if.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/*
 * conf = npf.config_create()
 */
static int
lua_npf_config_create(lua_State *L)
{
  nl_config_t *conf, *confx;

  conf = npf_config_create();
  confx = lua_newuserdata(L, sizeof(nl_config_t*));

  memmove(confx, conf, sizeof(nl_config_t*));
  npf_config_destroy(conf);
  luaL_getmetatable(L, "nl_config_t");
  lua_setmetatable(L, 1);
  return 1;
}

/*
 * status? = npf.config_submit(conf, fd)
 */
static int
lua_npf_config_submit(lua_State *L)
{
  nl_config_t *conf;
  int fd, status;

  conf = luaL_checkudata(L, 1, "nl_config_t");
  fd = luaL_checkinteger(L, 2);
  status = npf_config_submit(conf, fd);

  lua_pushinteger(L, status);
  return 1;
}

/*
 * status? = npf.config_flush(fd)
 */
static int
lua_npf_config_flush(lua_State *L)
{
  int fd, status;

  fd = luaL_checkinteger(L, 1);
  status = npf_config_flush(fd);

  lua_pushinteger(L, status);
  return 1;
}

/*
 * rule = npf.rule_create(name, attrs, interface)
 *
 * The name may be nil. The interface is a string, or "*" to represent any
 * interface.
 *
 * if_nametoindex() returns 0 if the interface with the given name does not
 * exist (i.e. it's an error). However, npf_rule_create()'s if_idx argument
 * may be 0 on purpose, to signify that the rule should apply to all
 * interfaces. So that's why we define the "*" semantics here.
 */
static int
lua_npf_rule_create(lua_State *L)
{
  char *name, *interface;
  uint32_t attrs;
  unsigned int if_idx;
  nl_rule_t *rule, *rulex;

  name = lua_isnil(L, 1) ? NULL : (char *)luaL_checkstring(L, 1);
  attrs = (uint32_t)luaL_checkinteger(L, 2);
  interface = (char *)luaL_checkstring(L, 3);
  lua_pop(L, 3);
  if_idx = if_nametoindex(interface);

  if (!strcmp(interface, "*")) {
    if_idx = 0;
  } else {
    if (if_idx == 0)
      luaL_error(L, "interface \"%s\" does not exist", interface);
  }

  rule = npf_rule_create(name, attrs, if_idx);

  if (rule == NULL)
    luaL_error(L, "could not create rule \"%s\"", name);

  rulex = lua_newuserdata(L, sizeof(nl_rule_t*));
  memmove(rulex, rule, sizeof(nl_rule_t*));

  luaL_getmetatable(L, "nl_rule_t");
  lua_setmetatable(L, 1);
  return 1;
}

static int
lua_npf_rule_setcode(lua_State *L)
{
  return 0;
}

/*
 * bool = npf.rule_exists(conf, name)
 *
 * XXX This segfaults! I have an IDEA why, I want to think it has something
 * to do with the mysterious sizeof()/incomplete type thing.
 *
 * Either that, npf_rule_exists_p() itself is messed up, but I seriously
 * doubt that...
 */
static int
lua_npf_rule_exists_p(lua_State *L)
{
  nl_config_t *conf;
  char *name;
  
  conf = luaL_checkudata(L, 1, "nl_config_t");
  name = (char *)luaL_checkstring(L, 2);
  lua_pop(L, 2);
  
  lua_pushboolean(L, npf_rule_exists_p(conf, name));
  return 1;
}

/*
 * status? = npf.rule_insert(conf, parent_rule, rule, priority)
 *
 * parent_rule may be nil.
 */
static int
lua_npf_rule_insert(lua_State *L)
{
  nl_config_t *conf;
  nl_rule_t *parent_rule, *rule;
  pri_t priority;
  int status;

  conf = luaL_checkudata(L, 1, "nl_config_t");
  parent_rule = lua_isnil(L, 2) ? NULL : luaL_checkudata(L, 2, "nl_rule_t");
  rule = luaL_checkudata(L, 3, "nl_rule_t");
  priority = (pri_t)lua_tointeger(L, 4);
  lua_pop(L, 4);

  status = npf_rule_insert(conf, parent_rule, rule, priority);

  lua_pushinteger(L, status);
  return 1;
}

/*
 * rproc = npf_rproc_create(name)
 */
static int
lua_npf_rproc_create(lua_State *L)
{
  nl_rproc_t *rproc, *rprocx;
  char *name;

  name = (char *)luaL_checkstring(L, 1);
  lua_pop(L, 1);

  rproc = npf_rproc_create(name);

  if (rproc == NULL)
    luaL_error(L, "could not create rproc \"%s\"", name);

  rprocx = lua_newuserdata(L, sizeof(nl_rproc_t*));
  memmove(rprocx, rproc, sizeof(nl_rproc_t*));

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
 * table = npf.table_create(index, type)
 */
static int
lua_npf_table_create(lua_State *L)
{
  int index, type;
  nl_table_t *table, *tablex;

  index = luaL_checkinteger(L, 1);
  type = luaL_checkinteger(L, 2);
  lua_pop(L, 2);

  table = npf_table_create(index, type);

  if (table == NULL)
    luaL_error(L, "could not create table");

  tablex = lua_newuserdata(L, sizeof(nl_table_t*));
  memmove(tablex, table, sizeof(nl_table_t*));
  npf_table_destroy(table);

  luaL_getmetatable(L, "nl_table_t");
  lua_setmetatable(L, 1);
  return 1;
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
  nl_config_t *conf;
  nl_table_t *table;
  int status;

  conf = luaL_checkudata(L, 1, "nl_config_t");
  table = luaL_checkudata(L, 2, "nl_table_t");
  status = npf_table_insert(conf, table);

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

static luaL_Reg npf_funcs[] = {
  {"config_create", lua_npf_config_create},
  {"config_submit", lua_npf_config_submit},
  {"config_flush", lua_npf_config_flush},

  {"rule_create", lua_npf_rule_create},
  {"rule_setcode", lua_npf_rule_setcode},
  {"rule_exists", lua_npf_rule_exists_p}, /* notice no "_p" */
  {"rule_insert", lua_npf_rule_insert},

  {"rproc_create", lua_npf_rproc_create},
  {"rproc_exists", lua_npf_rproc_exists_p}, /* notice no "_p" */
  {"rproc_insert", lua_npf_rproc_insert},

  {"nat_create", lua_npf_nat_create},
  {"nat_insert", lua_npf_nat_insert},

  {"table_create", lua_npf_table_create},
  {"table_add_entry", lua_npf_table_add_entry},
  {"table_exists", lua_npf_table_exists_p}, /* notice no "_p" */
  {"table_insert", lua_npf_table_insert},

  {"update_rule", lua_npf_update_rule},
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
  {"RULE_DEFAULT", NPF_RULE_DEFAULT},
  {"RULE_FINAL", NPF_RULE_FINAL},
  {"RULE_STATEFUL", NPF_RULE_STATEFUL},
  {"RULE_RETRST", NPF_RULE_RETRST},
  {"RULE_RETICMP", NPF_RULE_RETICMP},
  {"RULE_IN", NPF_RULE_IN},
  {"RULE_OUT", NPF_RULE_OUT},

  {"CODE_NCODE", NPF_CODE_NCODE},
  {"PRI_NEXT", NPF_PRI_NEXT},

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

  luaL_openlibs(L);

  luaL_register(L, "npf", npf_funcs);
  luaL_newmetatable(L, "nl_config_t");
  luaL_newmetatable(L, "nl_rule_t");
  luaL_newmetatable(L, "nl_table_t");
  luaL_newmetatable(L, "nl_rproc_t");
  luaL_newmetatable(L, "nl_nat_t");

  i = 0;
  while (npf_consts[i].name != NULL) {
    lua_pushinteger(L, npf_consts[i].value);
    lua_setfield(L, -(lua_gettop(L)) + 1, npf_consts[i].name);
    i++;
  }

  return 1;
}
