local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Attempts to get statistics for one or more indices from an ElasticSearch cluster.
]]

---
-- @usage
-- nmap -p 9200 --script elasticsearch-indicies <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 9200/tcp open  wap-wsp syn-ack
-- | elasticsearch-cluster:
-- |   ElasticSearch Indexes
-- |
-- |     oauth:
-- |       total:
-- |         store:
-- |           size_in_bytes: 29070
-- |         indexing:
-- |           noop_update_total: 0
-- |           throttle_time_in_millis: 0
-- |           index_failed: 0
-- |           is_throttled: false
-- |           index_total: 0
-- |           index_time_in_millis: 0
-- |           index_current: 0
-- |           delete_current: 0
-- |           delete_total: 0
-- |           delete_time_in_millis: 0

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
    local indexes = get_results(host, port, "/_stats/indexing,store")

    if indexes and indexes.indices then
        for index, stats in pairs(indexes.indices) do tble[index] = stats end
    end

    return tble
end
