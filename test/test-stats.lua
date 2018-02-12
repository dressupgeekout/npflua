package.cpath = "../?.so"

local npf = require("npf")

local st = npf.stats()
for k, v in pairs(st) do
  print(k, v)
end

