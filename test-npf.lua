package.cpath = "./?.so"

local npf = require("npf")
local iface = "wm0"

if #arg > 0 then
  iface = arg[1]
end

local conf = npf.config.create()
local rule = npf.rule.create("myrule", 0, iface)
npf.rule.insert(conf, nil, rule)

local table = npf.table.create(1, 0, npf.TABLE_HASH)
print(npf.table.insert(conf, table))

-- XXX This segfaults...
-- jada: Not any more. :)
local res = npf.rule.exists(conf, "myrule")
print(res)

