package.cpath = "./?.so"
require("npf")

conf = npf.config_create()
rule = npf.rule_create("myrule", 0, "re0")
npf.rule_insert(conf, nil, rule, npf.PRI_NEXT)

table = npf.table_create(1, npf.TABLE_HASH)
print(npf.table_insert(conf, table))

-- XXX This segfaults...
--npf.rule_exists(conf, "myrule")
