/* DNS 优选工具 · 本地数据可视化面板
 *
 * 界面结构参考 https://bench.dash.2020818.xyz/ ：
 *   左侧筛选栏（服务器类型 / 地区胶囊标签）+ 右侧「指标标签页 + 大卡片横向柱状图 + 分页」。
 * 在此之上扩展了本工具特有的能力：
 *   - 四套评分公式切换（服务端 /api/rank 计算，与 CLI 完全同源）
 *   - 域名组（国内 / 国外 / 自定义 / 导入）筛选，绝不混用
 *   - 「当前系统 DNS」与「内网地址」标记，以及是否建议切换的结论
 *   - 同一 DNS 在不同公式下的排名变化对比
 *   - 延迟分布堆叠图（仅本次测试的结果可用）
 *   - 深色 / 浅色主题、搜索、全选 / 清除、复制服务器地址
 *
 * 所有排名都由服务端计算，页面只负责展示，因此 CLI、Web 与导出文件使用同一套评分代码。
 */
(function () {
  "use strict";

  var PER_PAGE = 50;
  var THEME_KEY = "dns-opti-theme";

  var state = {
    payload: null,
    formulas: [],
    formula: "comprehensive",
    ranking: null,
    // filters
    protocol: "",
    group: "",
    // region filtering (modelled on the reference site's region chips):
    // regions is a Set of region codes; null means "all regions selected", and
    // an empty Set means "nothing selected" (which shows no rows, because a
    // region filter with nothing chosen is a deliberate empty selection).
    regions: null,
    allRegions: [],
    regionSearch: "",
    family: "",
    // policy 是过滤策略筛选（原生 / 安全），空字符串表示不筛选。
    policy: "",
    metric: "score",
    page: 1,
    charts: [],
    rankByFormula: {},
  };

  // 指标定义：对应参考站点的「总分 / 平均延迟 / 成功率 / QPS」标签页。
  var METRICS = [
    { id: "score", label: "综合得分", desc: "得分越高，表示在当前评分公式下综合表现越好。点击柱状图可以复制服务器地址。", order: "desc" },
    { id: "avg", label: "平均延迟", desc: "平均延迟(ms)越低，表示查询返回越快。数值过小也需留意是否被本地缓存或运营商劫持。", order: "asc" },
    { id: "p95", label: "P95 延迟", desc: "P95 表示最慢的 5% 请求的延迟上限，越小说明尾部体验越好。", order: "asc" },
    { id: "stddev", label: "延迟标准差", desc: "标准差越小，说明延迟越稳定、抖动越小。", order: "asc" },
    { id: "rate", label: "成功率", desc: "成功率越高，表示成功解析的查询占比越大。", order: "desc" },
  ];

  // ---------------- 通用工具 ----------------

  function $(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function fmtMs(v) {
    if (v === undefined || v === null || v <= 0) return "—";
    if (v < 10) return v.toFixed(1);
    if (v < 1000) return v.toFixed(0);
    return (v / 1000).toFixed(2) + "s";
  }

  function fmtPct(v) {
    if (v === undefined || v === null) return "—";
    return (v * 100).toFixed(1) + "%";
  }

  function rateClass(v) {
    if (v >= 0.99) return "rate-good";
    if (v >= 0.9) return "rate-mid";
    return "rate-bad";
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function groupLabel(g) {
    return {
      cn: "国内域名", intl: "国外域名", mixed: "国内外混合",
      custom: "自定义域名", imported: "导入数据",
    }[g] || g || "—";
  }

  // rowIP 返回一行的展示身份：IP 地址。
  //
  // 整个工具用 IP 而不是厂商名来标识一个解析器：一个厂商会发布多个地址
  // （AliDNS 在 4 种传输、2 个地址族下共有 8 个端点），只有地址是唯一的，
  // 而且地址正是用户要填进系统设置的东西。服务端的 ip 字段在主机名端点解析
  // 后才有值，因此这里回落到从 dns 字段里取出的主机。
  function rowIP(r) {
    var ip = (r.ip || "").trim();
    if (ip) return ip;
    return hostOf(r.dns || r.name || "");
  }

  // hostOf 从任意形态的端点中取出主机部分（与后端 model.HostOf 一致）。
  function hostOf(endpoint) {
    var e = String(endpoint || "").trim();
    if (!e) return "";
    var i = e.indexOf("://");
    if (i >= 0) e = e.slice(i + 3);
    var j = e.search(/[/?#]/);
    if (j >= 0) e = e.slice(0, j);
    var at = e.lastIndexOf("@");
    if (at >= 0) e = e.slice(at + 1);
    if (e.charAt(0) === "[") {
      var close = e.indexOf("]");
      return close >= 0 ? e.slice(1, close) : e.slice(1);
    }
    // 裸 IPv6 字面量：用“冒号后全是数字且前面没有冒号”来识别端口，
    // 否则会把 "2400:3200::1" 的最后一组当成端口截掉。
    var colon = e.lastIndexOf(":");
    if (colon >= 0) {
      var tail = e.slice(colon + 1);
      if (/^\d{1,5}$/.test(tail) && e.slice(0, colon).indexOf(":") === -1) {
        e = e.slice(0, colon);
      }
    }
    return e;
  }

  // copyTarget 返回「复制服务器地址」按钮应当复制的内容。
  //
  // 对明文协议（UDP）来说 IP 就是可直接填进系统设置的东西；但 DoH / DoT
  // 无法只靠一个 IP 配置（证书签发给了域名），所以加密协议复制完整端点地址，
  // 否则用户拿到的是一段填不进去的 IP。
  function copyTarget(r) {
    var p = String(r.protocol || "").toLowerCase();
    if (p === "doh" || p === "doh3" || p === "dot") return r.dns;
    return rowIP(r);
  }

  function serverKey(r) { return r.dns + "|" + r.protocol + "|" + r.group; }

  function protoLabel(p) { return String(p || "").toUpperCase(); }

  // policyLabelOf 用后端下发的名称渲染过滤策略。
  function policyLabelOf(value) {
    var v = String(value || "").trim().toLowerCase();
    var list = (state.payload && state.payload.policies) || [];
    for (var i = 0; i < list.length; i++) {
      if (String(list[i].value || "").toLowerCase() === v) return list[i].label || v;
    }
    return { native: "原生", security: "安全", adblock: "安全" }[v] || "未确认";
  }

  // policyClassOf 给出策略单元格的样式类。
  //
  // 旧的 "adblock" 按同一类处理：合并后它是「安全」的历史拼写，
  // 导入旧结果文件时不应变成一个没有样式的未知值。
  function policyClassOf(value) {
    var v = String(value || "").trim().toLowerCase();
    if (v === "security" || v === "adblock") return "pol pol-sec";
    return "pol pol-native";
  }

  function api(path, options) {
    return fetch(path, options).then(function (resp) {
      return resp.json().then(function (body) {
        if (!resp.ok) throw new Error((body && body.error) || "请求失败 (" + resp.status + ")");
        return body;
      });
    });
  }

  var toastTimer = null;

  function toast(message, isError) {
    var box = $("toast");
    box.textContent = message;
    box.style.borderLeft = isError ? "3px solid var(--danger)" : "3px solid var(--success)";
    box.classList.add("show");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { box.classList.remove("show"); }, 2600);
  }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(
        function () { toast("已复制: " + text, false); },
        function () { toast("复制失败，请手动选择", true); return null; }
      );
    }
    toast("当前浏览器不支持自动复制", true);
    return Promise.resolve();
  }

  // ---------------- 主题 ----------------

  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (e) { /* 隐私模式 */ }
    var theme = saved || (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    applyTheme(theme);

    $("btn-theme").addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* 忽略 */ }
      renderCharts();
      renderMetric();
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
  }

  // 读取主题相关颜色，供 ECharts 使用（ECharts 不认识 CSS 变量）。
  function palette() {
    var cs = getComputedStyle(document.documentElement);
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    return {
      dark: dark,
      fg: cs.getPropertyValue("--foreground").trim() || (dark ? "#ecedee" : "#11181c"),
      muted: cs.getPropertyValue("--muted").trim() || "#6b7280",
      border: cs.getPropertyValue("--border").trim() || "#e4e4e7",
      grid: dark ? "rgba(255,255,255,0.07)" : "rgba(17,17,17,0.07)",
      primary: "#006fee",
      bars: ["#7dd3fc", "#006fee", "#7828c8", "#17c964", "#f5a524", "#f31260", "#0ea5e9", "#14b8a6"],
    };
  }

  // ---------------- 数据集与筛选 ----------------

  // allRows 返回当前数据集里参与展示的全部行。
  function allRows() {
    var rows = (state.payload && state.payload.summary) || [];
    return rows.slice();
  }

  // filterRows 返回通过「协议 + 域名组 + 地区 + 地址族 + 过滤策略」筛选后的行。
  function filterRows(rows) {
    return rows.filter(function (r) {
      if (state.protocol && r.protocol !== state.protocol) return false;
      if (state.group && r.group !== state.group) return false;
      if (state.family && rowFamily(r) !== state.family) return false;
      if (state.policy && rowPolicy(r) !== state.policy) return false;
      // 地区筛选只在用户显式选择过之后生效：regions 为 null 表示「全部」，
      // 此时不应把任何行筛掉。
      if (state.regions && !state.regions.has(rowRegion(r))) return false;
      return true;
    });
  }

  // rowPolicy 返回一行的过滤策略；未标注的行视为未确认，与后端一致。
  function rowPolicy(r) {
    var v = String(r.policy || "").trim().toLowerCase();
    return v || "unknown";
  }

  // rowRegion 返回一行的地区码，缺失时归入 UNKNOWN，与后端的归类保持一致。
  function rowRegion(r) {
    var code = (r.region || "").trim().toUpperCase();
    return code || "UNKNOWN";
  }

  // rowFamily 返回一行的地址族；主机名端点在导入数据里可能没有该字段。
  function rowFamily(r) {
    var f = (r.family || "").trim().toLowerCase();
    return f || "any";
  }

  // regionLabelOf 用后端下发的名称渲染地区码，未知码回落为代码本身。
  function regionLabelOf(code) {
    var list = (state.payload && state.payload.regions) || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].code === code) return list[i].label || code;
    }
    return code;
  }

  // familyLabelOf 渲染地址族。
  function familyLabelOf(value) {
    if (value === "ipv4") return "IPv4";
    if (value === "ipv6") return "IPv6";
    return "双栈 / 未定";
  }

  // rankedRows 把当前公式的排名合并进筛选后的行，并按当前指标排序。
  function rankedRows() {
    var rows = filterRows(allRows());
    var byKey = {};
    if (state.ranking) {
      state.ranking.groups.forEach(function (g) {
        g.rows.forEach(function (r) { byKey[serverKey(r)] = r; });
      });
    }
    rows = rows.map(function (r) {
      var ranked = byKey[serverKey(r)];
      var out = Object.assign({}, r);
      out.score = ranked && ranked.score !== undefined ? ranked.score : 0;
      out.rank = ranked ? ranked.rank : 0;
      return out;
    });

    var metric = METRICS.filter(function (m) { return m.id === state.metric; })[0] || METRICS[0];
    var key = { score: "score", avg: "avg_ms", p95: "p95_ms", stddev: "stddev_ms", rate: "success_rate" }[metric.id];
    rows.sort(function (a, b) {
      // 完全没有成功查询的服务器（延迟 / 标准差均为 0）在「越小越好」的指标下
      // 会排到最前面，看起来像是最快的 —— 但它的 0ms 只是「没有数据」。
      // 因此这类行永远排在最后，与指标方向无关。
      var aDead = !a.success, bDead = !b.success;
      if (aDead !== bDead) return aDead ? 1 : -1;

      var av = a[key] || 0, bv = b[key] || 0;
      var d = metric.order === "asc" ? av - bv : bv - av;
      return d !== 0 ? d : (a.rank || 1e9) - (b.rank || 1e9);
    });
    return rows;
  }

  // ---------------- 头部 / 元信息 ----------------

  function renderSummaryFacet() {
    var p = state.payload;
    if (!p) { $("facet-summary").textContent = "—"; return; }
    var rows = allRows();
    var shown = filterRows(rows).length;
    var parts = [
      "来源：" + (p.label || p.source || "—"),
      "记录：" + shown + " / " + rows.length + " 条",
    ];
    var meta = p.meta || {};
    if (meta.timestamp) parts.push("生成：" + fmtTime(meta.timestamp));
    if (meta.combo) parts.push("组合模式：" + meta.combo);
    if (meta.ip_version) parts.push("地址族：" + meta.ip_version);
    $("facet-summary").textContent = parts.join(" · ");
  }

  // ---------------- 图表面板（标签页 + 横向柱状图 + 分页） ----------------

  // metricChart 保存当前指标图表的实例。切换指标 / 筛选时它的 DOM 容器会被
  // 整体替换，因此必须显式 dispose，否则每次重绘都会泄漏一个 ECharts 实例
  // （连同其 canvas 与事件监听）。
  var metricChart = null;

  function disposeMetricChart() {
    if (metricChart) {
      try { metricChart.dispose(); } catch (e) { /* 可能已随容器一起移除 */ }
      metricChart = null;
    }
  }

  function renderMetricTabs() {
    var host = $("metric-tabs");
    host.innerHTML = "";
    METRICS.forEach(function (m) {
      var b = el("button", "tab" + (state.metric === m.id ? " active" : ""), m.label);
      b.type = "button";
      b.setAttribute("role", "tab");
      b.addEventListener("click", function () {
        if (state.metric === m.id) return;
        state.metric = m.id;
        state.page = 1;
        renderMetricTabs();
        renderMetric();
      });
      host.appendChild(b);
    });
  }

  function renderMetric() {
    var host = $("panels");
    host.innerHTML = "";
    disposeMetricChart();
    var metric = METRICS.filter(function (m) { return m.id === state.metric; })[0] || METRICS[0];
    var rows = rankedRows();

    var panel = el("div", "panel");
    var head = el("div", "panel-head");
    var left = el("div");
    var title = el("h2", null, metric.label);
    left.appendChild(title);
    left.appendChild(el("p", "chart-desc", metric.desc));
    head.appendChild(left);

    if (rows.length > 0) {
      var pages = Math.max(1, Math.ceil(rows.length / PER_PAGE));
      if (state.page > pages) state.page = pages;
      var start = (state.page - 1) * PER_PAGE;
      var slice = rows.slice(start, start + PER_PAGE);

      var pager = el("div", "pager");
      pager.appendChild(el("span", "page-badge", slice.length + " 条"));
      pager.appendChild(el("span", null, "·"));
      pager.appendChild(el("span", null, "共 " + rows.length + " 条"));

      var prev = el("button", "page-btn", "‹");
      prev.type = "button";
      prev.disabled = state.page <= 1;
      prev.addEventListener("click", function () { state.page--; renderMetric(); });
      pager.appendChild(prev);

      pageNumbers(pages, state.page).forEach(function (n) {
        var b = el("button", "page-btn" + (n === state.page ? " active" : ""), String(n));
        b.type = "button";
        b.addEventListener("click", function () { state.page = n; renderMetric(); });
        pager.appendChild(b);
      });

      var next = el("button", "page-btn", "›");
      next.type = "button";
      next.disabled = state.page >= pages;
      next.addEventListener("click", function () { state.page++; renderMetric(); });
      pager.appendChild(next);
      head.appendChild(pager);

      // 图例：颜色含义
      var legend = el("div", "legend");
      var lg = el("span");
      var dot = el("i", "dot");
      dot.style.background = "#7dd3fc";
      lg.appendChild(dot);
      lg.appendChild(document.createTextNode("柱长 = " + metric.label + "，点击柱子可复制服务器地址"));
      legend.appendChild(lg);
      host.appendChild(panel);
      panel.appendChild(head);
      panel.appendChild(legend);

      var canvas = el("div", "chart-canvas");
      canvas.style.height = Math.max(240, slice.length * 22 + 90) + "px";
      panel.appendChild(canvas);
      drawHorizontalBars(canvas, slice, metric);
    } else {
      host.appendChild(panel);
      panel.appendChild(head);
      panel.appendChild(el("p", "empty", "当前筛选条件下没有数据。请调整左侧筛选，或重新运行测试 / 导入结果文件。"));
    }
  }

  // pageNumbers 生成分页按钮序列：页数少时全部列出，多了则首尾 + 当前附近。
  function pageNumbers(total, current) {
    if (total <= 7) {
      var all = [];
      for (var i = 1; i <= total; i++) all.push(i);
      return all;
    }
    var wanted = [1, total, current - 1, current, current + 1];
    if (current <= 3) wanted.push(2, 3, 4);
    if (current >= total - 2) wanted.push(total - 1, total - 2, total - 3);
    var seen = {};
    var nums = [];
    wanted.forEach(function (n) {
      if (n >= 1 && n <= total && !seen[n]) { seen[n] = true; nums.push(n); }
    });
    return nums.sort(function (a, b) { return a - b; });
  }

  // drawHorizontalBars 绘制参考站点风格的横向柱状图，点击柱子复制服务器地址。
  // rows 已按当前指标「最优在前」排序；颜色也按这个次序由深到浅，便于一眼看出优劣。
  function drawHorizontalBars(host, rows, metric) {
    if (typeof echarts === "undefined") {
      host.appendChild(el("p", "empty", "图表库未加载，排名与明细数据仍可正常查看。"));
      return;
    }
    var p = palette();
    var key = { score: "score", avg: "avg_ms", p95: "p95_ms", stddev: "stddev_ms", rate: "success_rate" }[metric.id];

    var values = rows.map(function (r) {
      var v = r[key] || 0;
      return metric.id === "rate" ? Number((v * 100).toFixed(1)) : Number(v.toFixed(2));
    });

    // 最优（rows[0]）颜色最深；最差最浅。
    var colors = rows.map(function (_, i) {
      var t = rows.length > 1 ? 1 - i / (rows.length - 1) : 1;
      return "rgba(0,111,238," + (0.25 + 0.65 * t).toFixed(2) + ")";
    });

    var labels = rows.map(function (r) {
      // 行标识固定为「IP + 协议 + 域名组」：同一个 IP 会分别出现在多个协议与
      // 域名组下，少了后两者就会有多行文字完全相同，无法区分。
      var text = rowIP(r) + " · " + protoLabel(r.protocol) + " · " + groupLabel(r.group);
      if (r.is_system) text += " [系统]";
      return text;
    });

    // ECharts 的 y 轴自下而上排列，反转后最优显示在最上方。
    var ordered = rows.slice().reverse();
    var orderedValues = values.slice().reverse();
    var orderedColors = colors.slice().reverse();
    var orderedLabels = labels.slice().reverse();

    var chart = echarts.init(host, null, { renderer: "canvas" });
    chart.setOption({
      animation: false,
      grid: { left: 8, right: 64, top: 8, bottom: 8, containLabel: true },
      tooltip: {
        trigger: "item",
        formatter: function (info) {
          var r = ordered[info.dataIndex];
          if (!r) return "";
          var lines = [
            "<b>" + rowIP(r) + "</b>",
            "协议: " + protoLabel(r.protocol),
            "域名组: " + groupLabel(r.group),
            "过滤策略: " + policyLabelOf(rowPolicy(r)),
            "地区: " + regionLabelOf(rowRegion(r)),
            "成功率: " + fmtPct(r.success_rate) + " (" + r.success + "/" + r.total + ")",
            "平均延迟: " + fmtMs(r.avg_ms) + " ms",
            "P95 延迟: " + fmtMs(r.p95_ms) + " ms",
            "标准差: " + fmtMs(r.stddev_ms) + " ms",
            "综合得分: " + (r.score || 0).toFixed(2),
          ];
          if (r.dns && rowIP(r) !== r.dns) lines.push("端点: " + r.dns);
          lines.push("<i style='opacity:.7'>点击可复制服务器地址</i>");
          return lines.join("<br/>");
        },
      },
      xAxis: {
        type: "value",
        axisLabel: { color: p.muted, fontSize: 11 },
        splitLine: { lineStyle: { color: p.grid } },
      },
      yAxis: {
        type: "category",
        data: orderedLabels,
        axisLabel: { color: p.fg, fontSize: 11, width: 230, overflow: "truncate" },
        axisLine: { lineStyle: { color: p.border } },
        axisTick: { show: false },
      },
      series: [{
        type: "bar",
        data: orderedValues.map(function (v, i) {
          return { value: v, itemStyle: { color: orderedColors[i] } };
        }),
        barMaxWidth: 22,
        label: {
          show: true,
          position: "right",
          color: p.muted,
          fontSize: 11,
          formatter: function (o) { return metric.id === "rate" ? o.value + "%" : String(o.value); },
        },
      }],
    });

    chart.on("click", function (params) {
      var r = ordered[params.dataIndex];
      if (r) copy(copyTarget(r));
    });
    metricChart = chart;
  }

  // ---------------- 概览卡片（扩展功能） ----------------

  function renderOverview() {
    var host = $("overview");
    host.innerHTML = "";
    if (!state.payload || allRows().length === 0) return;

    host.appendChild(rankShiftCard());
    host.appendChild(systemDNSCard());
  }

  // rankShiftCard 展示同一批数据在四套公式下的排名差异 —— 本工具的核心卖点。
  function rankShiftCard() {
    var card = el("div", "ov-card");
    card.appendChild(el("h3", null, "同一 DNS 在不同公式下的排名变化"));
    card.appendChild(el("p", "hint", "排名变化说明该服务器的「快 / 稳 / 尾部延迟」取舍不同，请按使用场景选择公式。"));

    var rows = filterRows(allRows());
    if (rows.length === 0) {
      card.appendChild(el("p", "muted small", "无数据。"));
      return card;
    }

    // 以当前公式的排名为基准，展示其它公式下的位次变化。
    var current = state.rankByFormula[state.formula] || {};
    var otherIds = state.formulas.map(function (f) { return f.id; }).filter(function (id) { return id !== state.formula; });

    var moved = rows.map(function (r) {
      var k = serverKey(r);
      var base = current[k] ? current[k].rank : 0;
      var best = null;
      otherIds.forEach(function (id) {
        var m = state.rankByFormula[id];
        if (!m || !m[k] || !base) return;
        var delta = m[k].rank - base;
        if (best === null || Math.abs(delta) > Math.abs(best.delta)) {
          best = { delta: delta, name: (state.formulas.filter(function (f) { return f.id === id; })[0] || {}).name || id };
        }
      });
      return { row: r, base: base, best: best };
    }).filter(function (x) { return x.base && x.best && x.best.delta !== 0; });

    moved.sort(function (a, b) { return Math.abs(b.best.delta) - Math.abs(a.best.delta); });

    if (moved.length === 0) {
      card.appendChild(el("p", "muted small", "在当前筛选范围内，四套公式给出的排名一致。"));
      return card;
    }

    moved.slice(0, 6).forEach(function (x) {
      var line = el("div", "ov-row");
      line.appendChild(el("span", "k", rowIP(x.row) + " · " + protoLabel(x.row.protocol) + "（" + x.best.name + "）"));
      var span = el("span", "rank-shift " + (x.best.delta < 0 ? "rank-up" : "rank-down"),
        (x.best.delta < 0 ? "↑" : "↓") + Math.abs(x.best.delta) + " 位");
      span.title = "基准排名 #" + x.base + " → 该公式 #" + (x.base + x.best.delta);
      line.appendChild(span);
      card.appendChild(line);
    });
    return card;
  }

  // bestOfGroup 返回某个域名组在当前公式下的最优行（第 1 名）。
  // 取完整数据集而非筛选后的行，这样即使系统 DNS 被单独筛出，也仍有可比的基准。
  function bestOfGroup(group) {
    var map = state.rankByFormula[state.formula] || {};
    var best = null;
    Object.keys(map).forEach(function (k) {
      var r = map[k];
      if (r.group !== group) return;
      if (!best || r.rank < best.rank) best = r;
    });
    return best;
  }

  // systemDNSCard 给出当前系统 DNS 的结论，并对内网地址给出警告。
  function systemDNSCard() {
    var card = el("div", "ov-card");
    card.appendChild(el("h3", null, "当前系统 DNS"));

    var rows = filterRows(allRows());
    var sys = rows.filter(function (r) { return r.is_system; });
    if (sys.length === 0) {
      card.appendChild(el("p", "hint", "本次数据中没有标记为「当前系统 DNS」的记录。测试时加上 --system-dns 即可纳入对比。"));
      return card;
    }

    sys.slice(0, 3).forEach(function (s) {
      // 最优服务器与名次都必须取自同一个域名组的完整排名：不同域名组的分数
      // 不可直接比较，而原始 summary 行也不带 rank 字段。
      var ranked = (state.rankByFormula[state.formula] || {})[serverKey(s)];
      var rank = ranked ? ranked.rank : 0;
      var best = bestOfGroup(s.group);
      var line = el("div", "ov-row");
      var left = el("span", "k", rowIP(s) + " · " + protoLabel(s.protocol) + " · " + groupLabel(s.group));
      if (s.is_private) {
        var t = el("span", "tag warn", "内网地址");
        left.appendChild(document.createTextNode(" "));
        left.appendChild(t);
      }
      line.appendChild(left);
      line.appendChild(el("span", "v", fmtPct(s.success_rate) + " / " + fmtMs(s.avg_ms) + "ms"));
      card.appendChild(line);

      var verdict = el("p", "verdict");
      // latencyGap = 系统 DNS 比最优慢多少（负值表示系统 DNS 更快）。
      // 这里必须是 sys - best；写成 best - sys 会让「慢很多」变成负数而误判为「差距可忽略」。
      var latencyGap = best ? s.avg_ms - best.avg_ms : 0;
      var rateGap = best ? best.success_rate - s.success_rate : 0;
      var rankText = rank ? "第 " + rank + " 名，" : "";

      if (s.success === 0) {
        verdict.classList.add("warn");
        verdict.textContent = "该系统 DNS 本次全部查询失败，建议切换到 " + (best ? best.dns : "其它服务器") + "。";
      } else if (rank === 1) {
        verdict.classList.add("ok");
        verdict.textContent = "该系统 DNS 在本域名组内已是第 1 名，无需更换。";
      } else if (best && latencyGap < 15 && rateGap <= 0.05) {
        verdict.classList.add("ok");
        verdict.textContent = "与最优（" + best.dns + "）差距在误差范围内，保留当前设置即可。";
      } else if (best) {
        verdict.classList.add("warn");
        verdict.textContent = "该系统 DNS " + rankText + "建议考虑 " + best.dns +
          (latencyGap > 0 ? "（平均延迟可降低约 " + fmtMs(latencyGap) + " ms）" : "") +
          (rateGap > 0 ? "（成功率可提升约 " + fmtPct(rateGap) + "）" : "") + "。";
      } else {
        verdict.classList.add("warn");
        verdict.textContent = "该系统 DNS " + rankText + "可切换到更优的服务器。";
      }

      if (s.is_private) {
        verdict.classList.add("warn");
        verdict.textContent += " 注意：该地址属于内网 / 环回 / 链路本地保留网段，通常用于路由器、公司或 VPN 内部解析，" +
          "更换为公共 DNS 可能导致内部域名（如 .local、公司内网域名）无法解析，请谨慎。";
      }
      card.appendChild(verdict);
    });
    return card;
  }

  // ---------------- 延迟分布 ----------------

  // renderCharts 重绘全部图表：指标柱状图 + 延迟分布图。
  function renderCharts() {
    var host = $("charts");
    host.innerHTML = "";
    disposeCharts();
    renderMetric();

    var hist = state.payload && state.payload.histogram;
    $("hist-note").textContent = hist && hist.labels
      ? "成功查询落在各延迟区间的数量，按当前筛选（前 6 名堆叠）"
      : "该数据源不含每次查询延迟（导入结果或仅含汇总的导出文件），无法绘制分布图";

    if (!hist || !hist.labels) {
      host.appendChild(el("p", "empty", "延迟分布仅对本次测试的结果可用。"));
      return;
    }

    var rows = rankedRows().slice(0, 6).filter(function (r) {
      return hist.counts[serverKey(r)];
    });
    if (rows.length === 0) {
      host.appendChild(el("p", "empty", "当前筛选条件下没有可绘制的分布数据。"));
      return;
    }

    var box = el("div", "chart-box");
    box.appendChild(el("div", "chart-title", "延迟分布（成功查询数）"));
    var canvas = el("div", "chart-canvas");
    canvas.style.height = "340px";
    box.appendChild(canvas);
    host.appendChild(box);

    if (typeof echarts === "undefined") {
      box.replaceChildren(el("p", "empty", "图表库未加载。"));
      return;
    }

    var p = palette();
    var series = rows.map(function (r, i) {
      return {
        name: rowIP(r) + " · " + protoLabel(r.protocol),
        type: "bar",
        stack: "total",
        barMaxWidth: 46,
        itemStyle: { color: p.bars[i % p.bars.length] },
        data: hist.counts[serverKey(r)],
      };
    });

    var chart = echarts.init(canvas, null, { renderer: "canvas" });
    chart.setOption({
      animation: false,
      grid: { left: 8, right: 16, top: 12, bottom: 8, containLabel: true },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      legend: { type: "scroll", bottom: 0, textStyle: { color: p.muted, fontSize: 11 } },
      xAxis: {
        type: "category",
        data: hist.labels,
        axisLabel: { color: p.fg, fontSize: 11, interval: 0, rotate: 20 },
        axisLine: { lineStyle: { color: p.border } },
      },
      yAxis: {
        type: "value",
        name: "查询数",
        nameTextStyle: { color: p.muted, fontSize: 11 },
        axisLabel: { color: p.muted, fontSize: 11 },
        splitLine: { lineStyle: { color: p.grid } },
      },
      series: series,
    });
    state.charts.push(chart);
    host.setAttribute("data-rendered", "1");
  }

  // disposeCharts 释放所有图表实例（延迟分布图 + 指标图）。
  function disposeCharts() {
    disposeMetricChart();
    state.charts.forEach(function (c) {
      try { c.dispose(); } catch (e) { /* 图表可能已被移除 */ }
    });
    state.charts = [];
  }

  // ---------------- 明细表 ----------------

  function renderTable() {
    var tbody = document.querySelector("#detail-table tbody");
    tbody.innerHTML = "";
    var rows = rankedRows();
    $("table-count").textContent = "共 " + rows.length + " 条记录";

    rows.forEach(function (r) {
      var tr = document.createElement("tr");

      function td(text, cls) {
        var c = el("td", cls || null, text);
        tr.appendChild(c);
        return c;
      }

      // 首列是 IP 身份：整个界面用它标识一台服务器，而不是厂商名。
      var nameTd = el("td", "name");
      var ipText = rowIP(r) || "—";
      var ipSpan = el("span", "ip", ipText);
      ipSpan.title = "点击复制 " + ipText;
      ipSpan.addEventListener("click", function () { copy(copyTarget(r)); });
      nameTd.appendChild(ipSpan);
      var tags = el("span", "tag-cell");
      if (r.is_system) tags.appendChild(el("span", "tag sys", "当前系统"));
      if (r.is_private) tags.appendChild(el("span", "tag warn", "内网"));
      if (tags.childNodes.length) { nameTd.appendChild(document.createTextNode(" ")); nameTd.appendChild(tags); }
      // 主机名端点（DoH / DoT）的 IP 是解析出来的，端点本身仍要看得到：
      // 证书签发给域名，只给 IP 的话用户没法配置。
      if (r.dns && r.dns !== ipText) {
        var ep = el("span", "ep", r.dns);
        ep.title = "端点地址";
        nameTd.appendChild(document.createElement("br"));
        nameTd.appendChild(ep);
      }
      tr.appendChild(nameTd);

      td(protoLabel(r.protocol));
      td(groupLabel(r.group));
      var regionTd = td(regionLabelOf(rowRegion(r)));
      regionTd.title = rowRegion(r);
      var policyTd = td(policyLabelOf(rowPolicy(r)), policyClassOf(rowPolicy(r)));
      policyTd.title = "该解析器对外公布的域名过滤行为";
      td(familyLabelOf(rowFamily(r)));
      var rateCell = td(fmtPct(r.success_rate), rateClass(r.success_rate));
      rateCell.title = r.success + " / " + r.total;
      td(r.success + " / " + r.total, "num");
      td(fmtMs(r.avg_ms), "num");
      td(fmtMs(r.p95_ms), "num");
      td(fmtMs(r.stddev_ms), "num");
      var sCell = td(r.score ? r.score.toFixed(2) : "—", "num");
      sCell.title = "得分随所选公式变化";
      tbody.appendChild(tr);
    });

    if (rows.length === 0) {
      var tr = document.createElement("tr");
      var c = el("td", "empty", "当前筛选条件下没有数据。");
      c.colSpan = 12;
      tr.appendChild(c);
      tbody.appendChild(tr);
    }
  }

  // ---------------- 筛选控件 ----------------

  function renderFacets() {
    var rows = allRows();

    // 服务器类型
    var protoHost = $("facet-proto");
    protoHost.innerHTML = "";
    var protos = [];
    rows.forEach(function (r) { if (r.protocol && protos.indexOf(r.protocol) === -1) protos.push(r.protocol); });
    ["udp", "dot", "doh", "doh3"].forEach(function (p) {
      if (protos.indexOf(p) === -1) protos.push(p);
    });
    addPill(protoHost, "全部", state.protocol === "", function () { state.protocol = ""; refreshFilters(); });
    protos.forEach(function (p) {
      addPill(protoHost, protoLabel(p), state.protocol === p, function () {
        state.protocol = state.protocol === p ? "" : p;
        refreshFilters();
      });
    });

    // 域名组
    var groupHost = $("facet-group");
    groupHost.innerHTML = "";
    var groups = [];
    rows.forEach(function (r) { if (r.group && groups.indexOf(r.group) === -1) groups.push(r.group); });
    groups = orderGroups(groups);
    addPill(groupHost, "全部", state.group === "", function () { state.group = ""; refreshFilters(); });
    groups.forEach(function (g) {
      addPill(groupHost, groupLabel(g), state.group === g, function () {
        state.group = state.group === g ? "" : g;
        refreshFilters();
      });
    });

    // 地址族
    var familyHost = $("facet-family");
    familyHost.innerHTML = "";
    var families = (state.payload && state.payload.families) || [];
    addPill(familyHost, "全部", state.family === "", function () { state.family = ""; refreshFilters(); });
    families.forEach(function (f) {
      addPill(familyHost, f.label + " " + f.count, state.family === f.value, function () {
        state.family = state.family === f.value ? "" : f.value;
        refreshFilters();
      });
    });

    // 过滤策略
    var policyHost = $("facet-policy");
    policyHost.innerHTML = "";
    var policyFacets = (state.payload && state.payload.policies) || [];
    addPill(policyHost, "全部", state.policy === "", function () { state.policy = ""; refreshFilters(); });
    policyFacets.forEach(function (f) {
      addPill(policyHost, f.label + " " + f.count, state.policy === f.value, function () {
        state.policy = state.policy === f.value ? "" : f.value;
        refreshFilters();
      });
      // 说明放进 title，避免在已经很长的侧栏里再堆一段文字。
      if (f.description) {
        var last = policyHost.lastChild;
        if (last) last.title = f.label + "：" + f.description;
      }
    });

    renderRegionFacet();
    renderPolicySummary();
  }

  // renderPolicySummary 说明当前策略筛选的含义，让用户不必记住三个词的区别。
  function renderPolicySummary() {
    var host = $("policy-summary");
    if (!host) return;
    var list = (state.payload && state.payload.policies) || [];
    if (list.length === 0) {
      host.textContent = "—";
      return;
    }
    if (!state.policy) {
      host.textContent = "全部策略：" + list.map(function (f) {
        return f.label + " " + f.count;
      }).join(" · ");
      return;
    }
    var hit = list.filter(function (f) { return f.value === state.policy; })[0];
    host.textContent = hit
      ? hit.label + "：" + (hit.description || "—") + "（" + shownCountForPolicy() + " 条匹配）"
      : "—";
  }

  // shownCountForPolicy 统计当前策略筛选下实际展示的行数。
  function shownCountForPolicy() {
    return filterRows(allRows()).length;
  }

  // renderRegionFacet 渲染地区码筛选：快捷分组 + 可搜索的地区码胶囊。
  // 参考站点用地区做属性筛选，这里沿用同样的思路，并按本工具的数据做了扩展
  // （特殊码 CDN / 内网 / 未知 也可以单独筛）。
  function renderRegionFacet() {
    var groups = (state.payload && state.payload.region_groups) || [];
    var regions = (state.payload && state.payload.regions) || [];
    state.allRegions = regions;

    // 快捷分组：点一下就等于「只选这一组」。
    var groupHost = $("facet-region-group");
    groupHost.innerHTML = "";
    if (groups.length === 0) {
      groupHost.appendChild(el("p", "muted small", "当前数据没有地区信息。"));
    }
    addPill(groupHost, "全部", state.regions === null, function () {
      selectAllRegions();
    });
    groups.forEach(function (g) {
      addPill(groupHost, g.label, regionsMatchGroup(g), function () {
        selectRegionGroup(g);
      });
    });

    renderRegionChips();
    renderRegionSummary();
  }

  // regionsMatchGroup 判断当前选择是否正好等于某个快捷分组。
  function regionsMatchGroup(g) {
    if (!state.regions) return false;
    var wanted = (g.codes || []).filter(function (c) { return regionCount(c) > 0; });
    if (wanted.length !== state.regions.size) return false;
    for (var i = 0; i < wanted.length; i++) {
      if (!state.regions.has(wanted[i])) return false;
    }
    return wanted.length > 0;
  }

  // regionCount 返回某个地区码在当前数据里的行数。
  function regionCount(code) {
    for (var i = 0; i < state.allRegions.length; i++) {
      if (state.allRegions[i].code === code) return state.allRegions[i].count;
    }
    return 0;
  }

  // renderRegionChips 渲染可逐个勾选的地区码胶囊，支持搜索过滤。
  function renderRegionChips() {
    var host = $("facet-regions");
    host.innerHTML = "";
    var q = state.regionSearch.trim().toLowerCase();

    var shown = state.allRegions.filter(function (r) {
      if (!q) return true;
      return (r.code + " " + (r.label || "")).toLowerCase().indexOf(q) !== -1;
    });
    if (shown.length === 0) {
      host.appendChild(el("p", "muted small", "没有匹配的地区。"));
      return;
    }

    shown.forEach(function (r) {
      var active = !!state.regions && state.regions.has(r.code);
      var b = el("button", "chip" + (active ? " on" : ""), r.code + " " + r.count);
      b.type = "button";
      b.title = (r.label || r.code) + "：当前数据中 " + r.count + " 条记录";
      b.addEventListener("click", function () {
        if (!state.regions) state.regions = new Set();
        if (state.regions.has(r.code)) state.regions.delete(r.code);
        else state.regions.add(r.code);
        refreshFilters();
      });
      host.appendChild(b);
    });
  }

  // renderRegionSummary 显示当前地区筛选的结论，让用户不必去数胶囊。
  function renderRegionSummary() {
    var host = $("region-summary");
    if (!state.payload || state.allRegions.length === 0) {
      host.textContent = "—";
      return;
    }
    if (state.regions === null) {
      host.textContent = "已选全部 " + state.allRegions.length + " 个地区";
      return;
    }
    if (state.regions.size === 0) {
      host.textContent = "未选择任何地区（当前不会显示任何数据）";
      return;
    }
    var total = 0;
    state.regions.forEach(function (code) { total += regionCount(code); });
    host.textContent = "已选 " + state.regions.size + " / " + state.allRegions.length +
      " 个地区，覆盖 " + total + " 条记录";
  }

  // selectAllRegions 清除地区筛选（返回「全部」状态）。
  function selectAllRegions() {
    state.regions = null;
    refreshFilters();
  }

  // selectRegionGroup 把选择替换为某个快捷分组里、且当前数据确实存在的地区码。
  function selectRegionGroup(g) {
    var next = new Set();
    (g.codes || []).forEach(function (code) {
      if (regionCount(code) > 0) next.add(code);
    });
    state.regions = next;
    refreshFilters();
  }

  // ensureRegionSelection 在数据集变化后初始化地区选择：默认全选。
  // 只有当数据集真的换了（地区码集合不同）才重置，避免用户导入新文件后
  // 之前的筛选被无声地丢掉又或被错误地沿用。
  function ensureRegionSelection() {
    var codes = state.allRegions.map(function (r) { return r.code; });
    if (state.regions === null) return; // 仍是「全部」，无需处理
    var kept = new Set();
    state.regions.forEach(function (code) {
      if (codes.indexOf(code) !== -1) kept.add(code);
    });
    state.regions = kept;
  }

  // orderGroups 让域名组按固定顺序展示（国内 → 国外 → 自定义 → 导入），
  // 未知分组追加在末尾，避免筛选栏顺序随数据抖动。
  function orderGroups(groups) {
    var canonical = ["cn", "intl", "custom", "imported"];
    var out = [];
    canonical.forEach(function (g) { if (groups.indexOf(g) >= 0) out.push(g); });
    groups.forEach(function (g) { if (out.indexOf(g) === -1) out.push(g); });
    return out;
  }

  function addPill(host, label, active, onClick) {
    var b = el("button", "pill" + (active ? " active" : ""), label);
    b.type = "button";
    b.addEventListener("click", onClick);
    host.appendChild(b);
  }

  // refreshFilters 重新计算并重绘所有依赖筛选的视图。
  function refreshFilters() {
    state.page = 1;
    renderFacets();
    renderSummaryFacet();
    refreshRanking().then(function () {
      renderTable();
      renderOverview();
      renderCharts();
    });
  }

  // ---------------- 公式 ----------------

  function renderFormula() {
    var host = $("formula-seg");
    host.innerHTML = "";
    state.formulas.forEach(function (f) {
      var b = el("button", "formula-opt" + (f.id === state.formula ? " active" : ""), f.name);
      b.type = "button";
      b.setAttribute("role", "tab");
      b.title = f.expr;
      b.addEventListener("click", function () {
        if (state.formula === f.id) return;
        state.formula = f.id;
        renderFormula();
        renderFormulaCard();
        refreshRanking().then(function () {
          renderTable();
          renderOverview();
          renderCharts();
        });
        toast("已切换到「" + f.name + "」，排名已重新计算");
      });
      host.appendChild(b);
    });
  }

  function renderFormulaCard() {
    var card = $("formula-card");
    var info = state.formulas.filter(function (f) { return f.id === state.formula; })[0];
    if (!info) { card.classList.add("hidden"); return; }
    card.innerHTML = "";

    var left = el("div");
    left.appendChild(el("h4", null, "公式"));
    left.appendChild(el("code", "formula-expr", info.expr));
    left.appendChild(el("h4", null, "适用场景"));
    left.appendChild(el("p", null, info.scenario));

    var right = el("div");
    right.appendChild(el("h4", null, "说明"));
    right.appendChild(el("p", null, info.desc));
    right.appendChild(el("p", "hint", "同一 DNS 在不同公式下排名可能变化，这正是提供多套公式的原因。"));

    card.appendChild(left);
    card.appendChild(right);
  }

  // refreshRanking 向服务端请求当前公式下的排名，并为「排名变化」卡片缓存其它公式的结果。
  function refreshRanking() {
    var rows = allRows();
    var ids = state.formulas.map(function (f) { return f.id; });
    return Promise.all(ids.map(function (id) {
      return api("/api/rank", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ formula: id, protocol: "", summary: rows }),
      }).catch(function () { return { groups: [] }; });
    })).then(function (results) {
      state.rankByFormula = {};
      ids.forEach(function (id, i) {
        var byKey = {};
        (results[i].groups || []).forEach(function (g) {
          g.rows.forEach(function (r) { byKey[serverKey(r)] = r; });
        });
        state.rankByFormula[id] = byKey;
      });
      var current = state.rankByFormula[state.formula] || {};
      state.ranking = { groups: groupRanking(current) };
    }).catch(function (err) {
      toast("重新排名失败: " + err.message, true);
    });
  }

  // groupRanking 把扁平的排名映射按域名组重新聚合，供渲染使用。
  function groupRanking(byKey) {
    var buckets = {};
    var order = [];
    Object.keys(byKey).forEach(function (k) {
      var r = byKey[k];
      if (!buckets[r.group]) { buckets[r.group] = []; order.push(r.group); }
      buckets[r.group].push(r);
    });
    return order.map(function (g) {
      buckets[g].sort(function (a, b) { return a.rank - b.rank; });
      return { group: g, label: groupLabel(g), rows: buckets[g] };
    });
  }

  // ---------------- 导入 / 导出 ----------------

  function applyPayload(payload) {
    state.payload = payload;
    state.page = 1;
    // A new dataset gets a fresh region selection (all regions). Carrying the
    // previous selection over would silently hide rows whose region code the
    // new file does not contain.
    state.regions = null;
    state.regionSearch = "";
    if ($("region-search")) $("region-search").value = "";
    state.family = "";
    state.policy = "";
    renderFacets();
    renderSummaryFacet();
    renderTable();
    renderComboPanel();
    return refreshRanking().then(function () {
      renderTable();
      renderOverview();
      renderCharts();
    });
  }

  // renderComboPanel 渲染 UDP+DoH 组合模式的对比表。普通运行没有对比数据，
  // 此时整个面板隐藏。
  function renderComboPanel() {
    var panel = $("combo-panel");
    var tbody = document.querySelector("#combo-table tbody");
    if (!panel || !tbody) return;

    var comparisons = (state.payload && state.payload.comparisons) || [];
    if (comparisons.length === 0) {
      panel.hidden = true;
      tbody.innerHTML = "";
      return;
    }
    panel.hidden = false;
    tbody.innerHTML = "";

    var comparable = 0, sum = 0;
    comparisons.forEach(function (c) {
      var tr = document.createElement("tr");

      function td(text, cls, title) {
        var cell = el("td", cls || null, text);
        if (title) cell.title = title;
        tr.appendChild(cell);
        return cell;
      }

      var nameTd = el("td", "name");
      var label = c.name || (c.udp && c.udp.name) || (c.doh && c.doh.name) || "—";
      var endpoints = Math.max(
        (c.udp && c.udp.endpoints) || 0,
        (c.doh && c.doh.endpoints) || 0
      );
      nameTd.appendChild(document.createTextNode(label));
      if (endpoints > 1) {
        nameTd.appendChild(document.createTextNode(" "));
        nameTd.appendChild(el("span", "tag", endpoints + " 个端点"));
      }
      tr.appendChild(nameTd);

      td(c.region ? regionLabelOf(c.region) : "—", null, c.region || "");

      [c.udp, c.doh].forEach(function (side) {
        if (!side || !side.total) {
          td("—", "num muted");
          td("—", "num muted");
          return;
        }
        var rateCell = td(fmtPct(side.success_rate), "num " + rateClass(side.success_rate));
        rateCell.title = side.success + " / " + side.total;
        td(side.success ? fmtMs(side.avg_ms) : "—", "num");
      });

      // Only a comparison where both transports answered is meaningful; a
      // missing side would otherwise read as "0 ms".
      if (c.comparable) {
        comparable++;
        sum += c.avg_delta_ms;
        var d = c.avg_delta_ms;
        var cls = d > 15 ? "num warn" : (d < -1 ? "num good" : "num");
        td(signedMs(d), cls, "DoH 平均延迟 − UDP 平均延迟");
      } else {
        td("—", "num muted", "两侧没有同时成功，无法比较");
      }

      tbody.appendChild(tr);
    });

    var note = $("combo-note");
    if (note) {
      if (comparable === 0) {
        note.textContent = "没有任何服务商的两种传输都成功，无法给出对比结论（常见原因：到 DoH 端点的 443 端口被阻断）。";
      } else {
        var avg = sum / comparable;
        note.textContent = "可对比 " + comparable + " 组；DoH 平均比 UDP " +
          (avg > 1 ? "慢 " + fmtMs(avg) + "ms" : (avg < -1 ? "快 " + fmtMs(-avg) + "ms" : "基本持平")) + "。";
      }
    }
  }

  // signedMs 带符号渲染毫秒差值。
  function signedMs(v) {
    if (!v) return "0";
    return (v > 0 ? "+" : "-") + fmtMs(Math.abs(v)) + "ms";
  }

  function setupActions() {
    $("btn-import").addEventListener("click", function () { $("file-input").click(); });
    $("btn-export").addEventListener("click", function () {
      if (!state.payload || allRows().length === 0) { toast("当前没有可导出的数据", true); return; }
      window.location.href = "/api/export";
    });

    $("file-input").addEventListener("change", function (ev) {
      var file = ev.target.files && ev.target.files[0];
      if (!file) return;
      if (!/\.json$/i.test(file.name)) { toast("仅支持 .json 结果文件", true); ev.target.value = ""; return; }
      var reader = new FileReader();
      reader.onload = function () {
        fetch("/api/import?name=" + encodeURIComponent(file.name), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: reader.result,
        }).then(function (resp) {
          return resp.json().then(function (b) {
            if (!resp.ok) throw new Error((b && b.error) || "导入失败");
            return b;
          });
        }).then(function (payload) {
          toast("已导入 " + file.name + "（识别为 " + (payload.label || "未知格式") + "）");
          return applyPayload(payload);
        }).catch(function (err) { toast("导入失败: " + err.message, true); });
      };
      reader.readAsText(file);
      ev.target.value = "";
    });

    // 地区码筛选的批量操作。地区选择用 Set 表达：null = 全部，空 Set = 一个都不选。
    $("btn-region-all").addEventListener("click", selectAllRegions);
    $("btn-region-none").addEventListener("click", function () {
      state.regions = new Set();
      refreshFilters();
    });
    $("btn-region-invert").addEventListener("click", function () {
      var next = new Set();
      state.allRegions.forEach(function (r) {
        var on = !!state.regions && state.regions.has(r.code);
        if (!on) next.add(r.code);
      });
      state.regions = next;
      refreshFilters();
    });

    var regionTimer = null;
    $("region-search").addEventListener("input", function (ev) {
      var v = ev.target.value;
      if (regionTimer) clearTimeout(regionTimer);
      regionTimer = setTimeout(function () {
        state.regionSearch = v;
        renderRegionChips();
      }, 150);
    });

    $("btn-reset").addEventListener("click", function () {
      state.protocol = "";
      state.group = "";
      state.regions = null;
      state.regionSearch = "";
      state.family = "";
      state.policy = "";
      $("region-search").value = "";
      refreshFilters();
      toast("筛选已重置");
    });
    $("btn-reload").addEventListener("click", function () {
      api("/api/result").then(function (p) {
        if (!p.summary || p.summary.length === 0) { toast("服务端没有数据可供载入", true); return; }
        return applyPayload(p).then(function () { toast("已重新载入数据"); });
      }).catch(function (e) { toast("载入失败: " + e.message, true); });
    });

    $("btn-formula-info").addEventListener("click", function () {
      $("formula-card").classList.toggle("hidden");
    });
    $("btn-collapse").addEventListener("click", function () {
      $("sidebar").classList.toggle("collapsed");
    });

    window.addEventListener("resize", function () {
      state.charts.forEach(function (c) { try { c.resize(); } catch (e) { /* 忽略 */ } });
    });
  }

  // ---------------- 启动 ----------------

  function boot() {
    initTheme();
    setupActions();

    Promise.all([api("/api/formulas"), api("/api/result")])
      .then(function (res) {
        var f = res[0], payload = res[1];
        state.formulas = f.formulas || [];
        state.formula = f.active || "comprehensive";
        renderFormula();
        renderFormulaCard();
        renderMetricTabs();

        if (!payload.summary || payload.summary.length === 0) {
          state.payload = payload;
          state.regions = null;
          state.allRegions = payload.regions || [];
          renderFacets();
          renderSummaryFacet();
          renderMetric();
          renderTable();
          renderOverview();
          renderCharts();
          renderComboPanel();
          toast("尚无数据：点击右上角「读取分析」导入结果 JSON", false);
          return;
        }
        return applyPayload(payload);
      })
      .catch(function (err) {
        toast("初始化失败: " + err.message, true);
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
