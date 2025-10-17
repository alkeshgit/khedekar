-- htaccess.lua — simplified .htaccess parser for OpenResty
-- Purpose: support common RewriteEngine/RewriteCond/RewriteRule and basic Redirect directives
-- Notes: ignores unsupported Apache-only directives and flags (E, P, ...), protects against redirect loops.
-- Install: add `lua_shared_dict ht 10m;` in nginx http {} and `access_by_lua_file /path/to/htaccess.lua;` in your server block.

local ngx_re = require "ngx.re"
local lfs = require "lfs"
local ngx = ngx

local shared = ngx.shared.ht
if not shared then
    ngx.log(ngx.ERR, "lua_shared_dict 'ht' not configured — please add 'lua_shared_dict ht 10m;' to http {}")
end

local function read_file(path)
    local f, err = io.open(path, "r")
    if not f then return nil, err end
    local data = f:read("*a")
    f:close()
    return data
end

local function file_mtime(path)
    local attr = lfs.attributes(path)
    if not attr then return nil end
    return attr.modification
end

-- Parse simple directives from .htaccess content
local function parse_htaccess(content)
    local rules = {redirects = {}, rewrites = {}, base = nil}
    for line in content:gmatch("[^
]+") do
        line = line:match("^%s*(.-)%s*$")
        if line == "" or line:match("^#") then goto continue end

        local lower = line:lower()
        if lower:match("^rewriteengine%s+") then
            local val = line:match("^%s*RewriteEngine%s+(.+)$")
            rules.rewriteengine = (val and val:lower():match("on")) and true or false
        elseif lower:match("^rewriterule%s+") then
            -- RewriteRule pattern substitution [flags]
            local pat, sub, flags = line:match("^%s*RewriteRule%s+([^%s]+)%s+([^%s]+)%s*(%b[])?")
            if pat and sub then
                local fstr = flags and flags:sub(2,-2) or ""
                table.insert(rules.rewrites, {pattern = pat, substitution = sub, flags = fstr})
            end
        elseif lower:match("^rewritecond%s+") then
            -- We'll attach conditions to the most recent rule (simple approach)
            local cond = line:match("^%s*RewriteCond%s+(.+)$")
            if cond and #rules.rewrites > 0 then
                local last = rules.rewrites[#rules.rewrites]
                last.conds = last.conds or {}
                table.insert(last.conds, cond)
            end
        elseif lower:match("^redirect%s+") then
            -- Redirect [status] old new
            local parts = {}
            for p in line:gmatch("%S+") do table.insert(parts, p) end
            if #parts >= 3 then
                local status, from, to
                if tonumber(parts[2]) then status = tonumber(parts[2]); from = parts[3]; to = parts[4]
                else status = 302; from = parts[2]; to = parts[3] end
                table.insert(rules.redirects, {from = from, to = to, status = status})
            end
        elseif lower:match("^redirectmatch%s+") then
            local _, pat, to = line:match("^%s*RedirectMatch%s+(%d?%d?%d?)?%s*(%S+)%s+(%S+)")
            if pat and to then
                table.insert(rules.redirects, {from_regex = pat, to = to, status = tonumber(_ or 302)})
            end
        elseif lower:match("^setbase%s+") or lower:match("^rewritebase%s+") then
            local base = line:match("^%s*RewriteBase%s+(.+)$")
            rules.base = base
        end
        ::continue::
    end
    return rules
end

-- Evaluate a simple RewriteCond like %{REQUEST_URI} !^/foo
local function eval_cond(cond, ngx_vars)
    -- This is intentionally limited: supports patterns like %{VAR} PATTERN
    local var, pattern = cond:match("%%{([^}]+)}%s+(.+)")
    if not var then
        -- try negation prefix: -f, -d etc — ignore and return true for simplicity
        return true
    end
    local val = ngx_vars[var] or ngx.var[var:lower()] or ""
    local neg = false
    if pattern:sub(1,1) == "!" then neg = true; pattern = pattern:sub(2) end
    local ok, err = ngx_re.find(val, pattern, "jo")
    if err then
        ngx.log(ngx.ERR, "htaccess: cond regex error: ", err)
        return false
    end
    local matched = ok and true or false
    return neg and (not matched) or matched
end

-- Apply rewrites; returns new_uri or nil
local function apply_rewrites(rewrites, ngx_vars, orig_uri)
    for _, r in ipairs(rewrites) do
        -- Skip if RewriteEngine off
        if rewrites.rewriteengine == false then return nil end

        -- Evaluate conditions (if any)
        local cond_ok = true
        if r.conds then
            cond_ok = true
            for _, c in ipairs(r.conds) do
                if not eval_cond(c, ngx_vars) then cond_ok = false; break end
            end
        end
        if not cond_ok then goto continue end

        -- Flags handling
        local flags = {}
        if r.flags then
            for f in r.flags:gmatch("[^,]+") do flags[f:upper()] = true end
        end

        local from = r.pattern
        local is_regex = from:find('[%^%$%[%]().*+?]') ~= nil -- heuristic: contains regex special chars
        local m, err
        if is_regex then
            m, err = ngx_re.match(orig_uri, from, "jo")
            if err then ngx.log(ngx.ERR, "htaccess: rewrite regex error: ", err); goto continue end
            if not m then goto continue end
            -- build substitution using captures
            local new_uri = r.substitution:gsub([[\(\d+)]], function(w) return m[tonumber(w:sub(2))] or "" end)
            -- handle relative substitutions
            if not new_uri:match("^https?://") and new_uri:sub(1,1) ~= "/" then
                -- prepend base or keep as-is
                if r.substitution and r.substitution:sub(1,1) ~= "/" then new_uri = "/" .. new_uri end
            end

            -- Redirect flag
            if flags.R then
                local status = 302
                local code = r.flags:match("R=(%d%d%d)")
                if code then status = tonumber(code) end
                return {type = "redirect", uri = new_uri, status = status}
            end

            if flags.L then
                return {type = "rewrite", uri = new_uri}
            end

            return {type = "rewrite", uri = new_uri}
        else
            -- simple wildcard like ^old$ or plain string
            if orig_uri == from or ngx_re.match(orig_uri, from, "jo") then
                local new_uri = r.substitution
                if flags.R then
                    local status = 302
                    local code = r.flags:match("R=(%d%d%d)")
                    if code then status = tonumber(code) end
                    return {type = "redirect", uri = new_uri, status = status}
                end
                return {type = "rewrite", uri = new_uri}
            end
        end
        ::continue::
    end
    return nil
end

-- Apply redirects
local function apply_redirects(redirects, uri)
    for _, r in ipairs(redirects) do
        if r.from then
            if uri == r.from or ngx_re.match(uri, r.from, "jo") then
                return {type = "redirect", uri = r.to, status = r.status or 302}
            end
        elseif r.from_regex then
            local m = ngx_re.match(uri, r.from_regex, "jo")
            if m then return {type = "redirect", uri = r.to, status = r.status or 302} end
        end
    end
    return nil
end

-- Main entrypoint
local function handle()
    local docroot = ngx.var.document_root or ngx.var.realpath_root or ngx.var.root or ngx.var.web_root or ngx.var.basedir
    if not docroot then ngx.log(ngx.ERR, "htaccess: unable to determine document root"); return end

    local htpath = docroot .. "/.htaccess"
    local mtime = file_mtime(htpath)
    local cache_key = htpath .. ":" .. (mtime or "none")
    local cached = shared and shared:get(cache_key)
    local rules
    if cached then
        -- cached contains a token pointing to a serialized rules table in shared; as shared can't hold tables we'll store raw content in shared
        rules = shared:get(cache_key .. ":rules")
        if rules then rules = ngx.decode_base64(rules) end
        -- We expect rules to be a string (the content) — parse again to ensure live behavior
        if rules then rules = parse_htaccess(rules) end
    else
        local content, err = read_file(htpath)
        if not content then return end
        rules = parse_htaccess(content)
        if shared then
            -- store raw content; limit size caution
            local ok, serr = shared:set(cache_key, true)
            if ok then shared:set(cache_key .. ":rules", ngx.encode_base64(content)) end
        end
    end

    if not rules then return end

    -- Build ngx_vars for condition evaluation
    local ngx_vars = setmetatable({}, {__index = function(_, k) return ngx.var[k:lower()] end})
    local uri = ngx.var.uri
    local original_uri = uri
    local iteration = 0
    local max_iterations = 10

    -- First check explicit Redirect/RedirectMatch
    local rd = apply_redirects(rules.redirects or {}, uri)
    if rd then
        return ngx.redirect(rd.uri, rd.status)
    end

    while iteration < max_iterations do
        iteration = iteration + 1
        local res = apply_rewrites(rules.rewrites or {}, ngx_vars, uri)
        if not res then break end
        if res.type == "redirect" then
            return ngx.redirect(res.uri, res.status or 302)
        elseif res.type == "rewrite" then
            if res.uri == uri then break end
            uri = res.uri
            -- set_uri will internally rewrite to new uri
            ngx.req.set_uri(uri, true)
            -- continue loop to allow chained rewrites
        else
            break
        end
        if uri == original_uri then break end
    end

    if iteration >= max_iterations then
        ngx.log(ngx.ERR, "htaccess: possible rewrite loop detected for ", ngx.var.uri)
    end
end

-- Protect execution with pcall
local ok, err = pcall(handle)
if not ok then ngx.log(ngx.ERR, "htaccess.lua failed: ", err) end
