local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Attempts to get statistics for one or more indices from an ElasticSearch cluster.
]]

---
-- @usage
-- nmap -p 9200 --script elasticsearch-cluster <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 9200/tcp open  wap-wsp syn-ack
-- | elasticsearch-cluster:
-- |   count:
-- |     master: 1
-- |     data: 1
-- |     total: 1
-- |     coordinating_only: 0
-- |     ingest: 1
-- |   network_types:
-- |     http_types:
-- |       security4: 1
-- |     transport_types:
-- |       security4: 1
-- |   versions:
-- |     6.6.0
-- |   process:
-- |     open_file_descriptors:
-- |       max: 598
-- |       min: 598
-- |       avg: 598
-- |     cpu:
-- |       percent: 29
-- |   plugins:
-- |   jvm:
-- |     threads: 44
-- |     mem:
-- |       heap_max_in_bytes: 1056309248
-- |       heap_used_in_bytes: 711970312
-- |     versions:
-- |
-- |         vm_version: 25.392-b08
-- |         vm_vendor: Red Hat, Inc.
-- |         version: 1.8.0_392
-- |         count: 1
-- |         vm_name: OpenJDK 64-Bit Server VM
-- |     max_uptime_in_millis: 2113132189
-- |   fs:
-- |     available_in_bytes: 82688692224
-- |     total_in_bytes: 105552769024
-- |     free_in_bytes: 87214948352
-- |   os:
-- |     names:
-- |
-- |         count: 1
-- |         name: Linux
-- |     available_processors: 2
-- |     allocated_processors: 2
-- |     pretty_names:
-- |
-- |         pretty_name: CentOS Linux 7 (Core)
-- |         count: 1
-- |     mem:
-- |       free_percent: 4
-- |       free_in_bytes: 146464768
-- |       used_in_bytes: 3676925952
-- |       total_in_bytes: 3823390720
-- |_      used_percent: 96

author = "Damian Myerscough"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service({9200}, {"elasticsearch"})

function get_results(host, port, endpoint)
    local response = http.get(host, port, endpoint)
    local status = response.status

    status, body = json.parse(response.body)

    if status == nil or status == false then
        -- Something went really wrong out there
        -- According to the NSE way we will die silently rather than spam user with error messages
        return
    end

    return body
end

action = function(host, port)

    local tble = stdnse.output_table()
    local cluster = get_results(host, port, "_cluster/stats")

    if cluster and cluster.nodes then
        for index, stats in pairs(cluster.nodes) do tble[index] = stats end
    end

    return tble
end
