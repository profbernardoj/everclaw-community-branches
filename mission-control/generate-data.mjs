#!/usr/bin/env node
/**
 * Mission Control Data Generator
 *
 * Reads memory files, goals, and cron state to produce dashboard-data.json
 * for the Mission Control dashboard. Run nightly via cron or on demand.
 *
 * Usage: node generate-data.mjs
 */

import fs from "node:fs";
import path from "node:path";

const WORKSPACE = process.env.OPENCLAW_WORKSPACE || path.join(process.env.HOME, ".openclaw", "workspace");
const MEMORY_DIR = path.join(WORKSPACE, "memory");
const GOALS_DIR = path.join(MEMORY_DIR, "goals");
const USER_MD = path.join(WORKSPACE, "USER.md");
const MEMORY_MD = path.join(WORKSPACE, "MEMORY.md");
const OUTPUT = path.join(WORKSPACE, "mission-control", "dashboard-data.json");

// ─── Parse markdown helpers ─────────────────────────────────────────────────

function readFile(p) {
  try { return fs.readFileSync(p, "utf-8"); } catch { return ""; }
}

function extractSection(md, heading) {
  // Try ### then ## headings
  for (const prefix of ["###", "##"]) {
    const escaped = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`^${prefix}\\s+${escaped}\\s*$`, "im");
    const match = md.search(re);
    if (match === -1) continue;
    const rest = md.slice(match);
    // Skip the heading line itself
    const afterHeading = rest.indexOf("\n");
    if (afterHeading === -1) return rest.trim();
    const body = rest.slice(afterHeading);
    // Find next heading at same or higher level (### or ##)
    const nextH = body.search(/\n#{2,3}\s/);
    return (nextH > 0 ? rest.slice(0, afterHeading + nextH) : rest).trim();
  }
  return "";
}

function extractBullets(section) {
  return section
    .split("\n")
    .filter(l => l.match(/^[-*]\s/))
    .map(l => l.replace(/^[-*]\s+/, "").trim())
    .filter(Boolean);
}

// ─── Parse goals ────────────────────────────────────────────────────────────

function parseGoalFile(filepath) {
  const content = readFile(filepath);
  if (!content) return null;

  const nameMatch = content.match(/^#\s+(.+)/m);
  const name = nameMatch ? nameMatch[1].trim() : path.basename(filepath, ".md");

  // Extract emoji from name
  const emojiMatch = name.match(/^(\p{Emoji_Presentation}|\p{Emoji}\uFE0F?)/u);
  const emoji = emojiMatch ? emojiMatch[0] : "🎯";
  const cleanName = name.replace(/^(\p{Emoji_Presentation}|\p{Emoji}\uFE0F?)\s*/u, "").replace(/\s*—.*$/, "").trim();

  // Parse sections
  const vision = extractBullets(extractSection(content, "Vision"));
  const activeProjects = extractBullets(extractSection(content, "Active Projects"));
  const relationships = extractBullets(extractSection(content, "Relationships & Assets"));
  const currentVectors = extractBullets(extractSection(content, "Current Vectors"));
  const actionsTaken = extractBullets(extractSection(content, "Actions Taken")).filter(l => !l.includes("tracking starts"));
  const actionsSuggested = extractBullets(extractSection(content, "Actions Suggested")).filter(l => !l.includes("none yet"));
  const trackRecord = extractBullets(extractSection(content, "Track Record"));
  const objective = extractBullets(extractSection(content, "Objective"));
  const status = extractBullets(extractSection(content, "Status"));

  // Gather sub-goals from all parsed sections
  const subGoals = [];

  // Active projects are sub-goals
  activeProjects.forEach(p => {
    const boldMatch = p.match(/^\*\*(.+?)\*\*[:\s]*(.*)/);
    subGoals.push({
      title: boldMatch ? boldMatch[1] : p.slice(0, 80),
      detail: boldMatch ? boldMatch[2] : "",
      status: actionsTaken.length > 0 ? "in-progress" : "planned",
      source: "active-project",
    });
  });

  // Vision items are sub-goals if no active projects
  if (subGoals.length === 0) {
    vision.forEach(v => subGoals.push({ title: v.slice(0, 80), detail: "", status: "planned", source: "vision" }));
  }

  // Current vectors
  currentVectors.forEach(v => subGoals.push({ title: v.slice(0, 80), detail: "", status: "in-progress", source: "vector" }));

  // Relationships are context
  const context = [...relationships, ...trackRecord];

  return {
    id: path.basename(filepath, ".md"),
    emoji,
    name: cleanName,
    subGoals,
    actionsTaken,
    actionsSuggested,
    context,
    status: statusFromContent(content, actionsTaken),
    raw: content.slice(0, 2000),
  };
}

function statusFromContent(content, actions) {
  if (content.includes("Status: TODO") || content.includes("Status: PLANNED")) return "planned";
  if (actions.length > 0) return "active";
  if (content.includes("Status: DONE") || content.includes("Status: COMPLETE")) return "complete";
  return "tracking";
}

// ─── Parse USER.md for life goals ───────────────────────────────────────────

function parseLifeGoals() {
  const user = readFile(USER_MD);

  const goalDefs = [
    { id: "family-first", emoji: "👨‍👩‍👧‍👦", name: "Family First", section: "1. Family First", file: "great-commission-family.md" },
    { id: "christ-centered", emoji: "✝️", name: "Christ-Centered Family", section: "2. Christ-Centered Family", file: "great-commission-family.md" },
    { id: "great-commission", emoji: "⛪", name: "Great Commission", section: "3. Great Commission", file: "great-commission-family.md" },
    { id: "space-settlement", emoji: "🚀", name: "Space Settlement", section: "4. Space Settlement", file: "space-settlement.md" },
    { id: "abolition-state", emoji: "🏴", name: "Abolition of the State", section: "5. Abolition of the State", file: "abolition-of-state.md" },
    { id: "wealth-creation", emoji: "💰", name: "Wealth Creation for Others", section: "6. Wealth Creation for Others", file: "wealth-creation.md" },
  ];

  return goalDefs.map(def => {
    // Extract the section from USER.md for description
    const sectionContent = extractSection(user, def.section);
    const allLines = sectionContent
      .split("\n")
      .filter(l => !l.startsWith("#") && l.trim());
    const description = allLines
      .slice(0, 3)
      .map(l => l.replace(/^[-*]\s+/, "").trim())
      .join(" ")
      .slice(0, 200);

    // Merge with goal file data if it exists
    const goalFile = parseGoalFile(path.join(GOALS_DIR, def.file));

    // Derive sub-goals from USER.md section for this specific goal
    let subGoals = [];

    // Extract bullet points
    const bullets = allLines
      .filter(l => l.match(/^[-*]\s/))
      .map(l => l.replace(/^[-*]\s+/, "").trim())
      .filter(l => l && !l.includes("tracking starts") && !l.includes("none yet"));

    // Extract from "Current involvement:" subsections
    const involvementSection = sectionContent.match(/\*\*Current involvement:\*\*\s*\n([\s\S]+?)(?:\n\*\*|\n###|$)/);
    if (involvementSection) {
      involvementSection[1].split("\n")
        .filter(l => l.match(/^[-*]\s/))
        .map(l => l.replace(/^[-*]\s+/, "").trim())
        .filter(l => l)
        .forEach(item => subGoals.push({ title: item.slice(0, 100), detail: "", status: "active", source: "involvement" }));
    }

    // Add bullets as sub-goals
    bullets.forEach(b => {
      if (!subGoals.some(s => s.title === b.slice(0, 100))) {
        const boldMatch = b.match(/^\*\*(.+?)\*\*[:\s]*(.*)/);
        subGoals.push({
          title: boldMatch ? boldMatch[1] : b.slice(0, 100),
          detail: boldMatch ? boldMatch[2].slice(0, 150) : "",
          status: "planned",
          source: "user-md",
        });
      }
    });

    // Extract bold-prefixed lines as sub-goals (e.g. **Beliefs:** ...)
    const boldLines = allLines
      .filter(l => l.match(/^\*\*.+?\*\*/))
      .map(l => {
        const m = l.match(/^\*\*(.+?)\*\*[:\s]*(.*)/);
        return m ? { title: m[1], detail: m[2].slice(0, 150) } : null;
      })
      .filter(Boolean);
    boldLines.forEach(b => {
      if (!subGoals.some(s => s.title === b.title)) {
        subGoals.push({ title: b.title, detail: b.detail, status: "active", source: "user-md" });
      }
    });

    // If section is just a description paragraph (no bullets/bolds), use it as a single sub-goal
    if (subGoals.length === 0 && description) {
      subGoals.push({ title: description.slice(0, 100), detail: "", status: "active", source: "description" });
    }

    // Merge in goal file sub-goals
    if (goalFile?.subGoals?.length) {
      goalFile.subGoals.forEach(sg => {
        if (!subGoals.some(s => s.title === sg.title)) {
          subGoals.push(sg);
        }
      });
    }

    return {
      ...def,
      description,
      subGoals: subGoals.slice(0, 15), // Cap at 15 sub-goals per goal
      actionsTaken: goalFile?.actionsTaken || [],
      actionsSuggested: goalFile?.actionsSuggested || [],
      context: goalFile?.context || [],
      status: goalFile?.status || (subGoals.some(s => s.status === "active") ? "active" : "tracking"),
    };
  });
}

// ─── Parse additional goal files not in life goals ──────────────────────────

function parseAdditionalGoals() {
  const lifeGoalFiles = new Set([
    "great-commission-family.md",
    "space-settlement.md",
    "abolition-of-state.md",
    "wealth-creation.md",
  ]);

  try {
    return fs.readdirSync(GOALS_DIR)
      .filter(f => f.endsWith(".md") && !lifeGoalFiles.has(f))
      .map(f => parseGoalFile(path.join(GOALS_DIR, f)))
      .filter(Boolean);
  } catch {
    return [];
  }
}

// ─── Parse memory files for activity feed ───────────────────────────────────

function parseMemoryFiles() {
  const activities = [];

  try {
    const files = fs.readdirSync(MEMORY_DIR)
      .filter(f => f.match(/^2026-\d{2}-\d{2}/) && f.endsWith(".md"))
      .sort()
      .reverse()
      .slice(0, 14); // Last 2 weeks

    for (const file of files) {
      const content = readFile(path.join(MEMORY_DIR, file));
      const dateMatch = file.match(/^(\d{4}-\d{2}-\d{2})/);
      const date = dateMatch ? dateMatch[1] : file;

      // Split by ## headings
      const sections = content.split(/^## /m).slice(1);
      for (const section of sections) {
        const lines = section.split("\n");
        const title = lines[0].trim();
        const timeMatch = title.match(/\((\d{1,2}:\d{2}\s*(?:AM|PM|CST)?)\)/i);
        const time = timeMatch ? timeMatch[1].replace(" CST", "") : "00:00";

        // Classify type
        let type = "system";
        const lower = title.toLowerCase();
        if (lower.includes("security") || lower.includes("clawdstrike") || lower.includes("skillguard")) type = "security";
        else if (lower.includes("cron") || lower.includes("briefing") || lower.includes("schedule")) type = "cron";
        else if (lower.includes("config") || lower.includes("model") || lower.includes("fallback") || lower.includes("provider") || lower.includes("proxy")) type = "config";
        else if (lower.includes("email") || lower.includes("proton")) type = "email";
        else if (lower.includes("search") || lower.includes("web")) type = "search";
        else if (lower.includes("message") || lower.includes("signal") || lower.includes("telegram")) type = "message";
        else if (lower.includes("everclaw") || lower.includes("morpheus") || lower.includes("x402") || lower.includes("8004") || lower.includes("router")) type = "config";

        // Get first meaningful paragraph as description
        const desc = lines.slice(1)
          .filter(l => l.trim() && !l.startsWith("#") && !l.startsWith("```") && !l.startsWith("|"))
          .slice(0, 3)
          .map(l => l.replace(/^[-*]\s+/, "").replace(/\*\*/g, "").trim())
          .join(" ")
          .slice(0, 200);

        if (title && desc) {
          activities.push({
            time: `${date} ${time}`,
            date,
            type,
            title: title.replace(/\(\d{1,2}:\d{2}\s*(?:AM|PM|CST)?\)/i, "").trim(),
            desc,
          });
        }
      }
    }
  } catch (e) {
    console.error("Error parsing memory files:", e.message);
  }

  return activities.sort((a, b) => b.time.localeCompare(a.time));
}

// ─── Parse MEMORY.md for key facts ──────────────────────────────────────────

function parseMemoryMd() {
  const content = readFile(MEMORY_MD);
  const sections = content.split(/^## /m).slice(1);
  return sections.map(s => {
    const lines = s.split("\n");
    return {
      heading: lines[0].trim(),
      content: lines.slice(1).filter(l => l.trim()).join("\n").slice(0, 500),
    };
  });
}

// ─── Main ───────────────────────────────────────────────────────────────────

function main() {
  console.log("Generating Mission Control dashboard data...");

  const lifeGoals = parseLifeGoals();
  const additionalGoals = parseAdditionalGoals();
  const activities = parseMemoryFiles();
  const keyFacts = parseMemoryMd();

  const data = {
    generated: new Date().toISOString(),
    owner: "[REDACTED]",
    lifeGoals,
    additionalGoals,
    activities,
    keyFacts,
    stats: {
      totalActivities: activities.length,
      totalGoals: lifeGoals.length + additionalGoals.length,
      activeGoals: [...lifeGoals, ...additionalGoals].filter(g => g.status === "active").length,
      memoryFiles: fs.readdirSync(MEMORY_DIR).filter(f => f.endsWith(".md") && !fs.statSync(path.join(MEMORY_DIR, f)).isDirectory()).length,
    },
  };

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, JSON.stringify(data, null, 2));

  // Also inject data directly into index.html so it works from file:// protocol
  const htmlPath = path.join(path.dirname(OUTPUT), "index.html");
  try {
    let html = fs.readFileSync(htmlPath, "utf-8");
    const dataScript = `<script id="embedded-data">window.__DASHBOARD_DATA__ = ${JSON.stringify(data)};</script>`;
    // Replace existing embedded data or insert before closing </head>
    if (html.includes('<script id="embedded-data">')) {
      html = html.replace(/<script id="embedded-data">[\s\S]*?<\/script>/, dataScript);
    } else {
      html = html.replace('</head>', dataScript + '\n</head>');
    }
    fs.writeFileSync(htmlPath, html);
    console.log(`✅ Dashboard data embedded into index.html`);
  } catch (e) {
    console.error(`⚠️  Could not embed data into index.html: ${e.message}`);
  }

  console.log(`✅ Dashboard data written to ${OUTPUT}`);
  console.log(`   Activities: ${data.stats.totalActivities}`);
  console.log(`   Life Goals: ${lifeGoals.length}`);
  console.log(`   Additional Goals: ${additionalGoals.length}`);
  console.log(`   Key Facts: ${keyFacts.length}`);
}

main();
