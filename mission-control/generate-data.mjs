#!/usr/bin/env node
/**
 * Mission Control Data Generator (Generic)
 *
 * Reads memory files, goals, and workspace state to produce dashboard-data.json.
 * Auto-discovers goals from memory/goals/*.md — no hardcoded personal data.
 *
 * Usage: node generate-data.mjs
 */

import fs from "node:fs";
import path from "node:path";

// ─── CONFIGURE THESE ────────────────────────────────────────────────────────

const CONFIG = {
  ownerName: "Agent Owner", // Your name
  timezone: "America/Chicago", // Your timezone
};

// ─── Paths ──────────────────────────────────────────────────────────────────

const WORKSPACE = process.env.OPENCLAW_WORKSPACE || path.join(process.env.HOME, ".openclaw", "workspace");
const MEMORY_DIR = path.join(WORKSPACE, "memory");
const DAILY_DIR = path.join(MEMORY_DIR, "daily");
const GOALS_DIR = path.join(MEMORY_DIR, "goals");
const MEMORY_MD = path.join(WORKSPACE, "MEMORY.md");
const USER_MD = path.join(WORKSPACE, "USER.md");
const OUTPUT = path.join(WORKSPACE, "mission-control", "dashboard-data.json");

// ─── Helpers ────────────────────────────────────────────────────────────────

function readFile(p) {
  try { return fs.readFileSync(p, "utf-8"); } catch { return ""; }
}

function extractBullets(text) {
  return text.split("\n")
    .filter(l => l.match(/^[-*]\s/))
    .map(l => l.replace(/^[-*]\s+/, "").trim())
    .filter(Boolean);
}

// ─── Parse goals (auto-discover) ────────────────────────────────────────────

function parseGoalFile(filepath) {
  const content = readFile(filepath);
  if (!content) return null;

  const nameMatch = content.match(/^#\s+(.+)/m);
  const name = nameMatch ? nameMatch[1].trim() : path.basename(filepath, ".md");

  // Extract emoji
  const emojiMatch = name.match(/^(\p{Emoji_Presentation}|\p{Emoji}\uFE0F?)/u);
  const emoji = emojiMatch ? emojiMatch[0] : "🎯";
  const cleanName = name.replace(/^(\p{Emoji_Presentation}|\p{Emoji}\uFE0F?)\s*/u, "").replace(/\s*—.*$/, "").trim();

  // Find sections and extract bullets from each
  const sections = content.split(/^## /m).slice(1);
  const subGoals = [];
  const actionsTaken = [];
  const actionsSuggested = [];
  const context = [];

  for (const section of sections) {
    const lines = section.split("\n");
    const heading = lines[0].trim().toLowerCase();
    const bullets = extractBullets(section);

    if (heading.includes("active") || heading.includes("project") || heading.includes("current")) {
      bullets.forEach(b => subGoals.push({ title: b.slice(0, 100), status: "in-progress", source: heading }));
    } else if (heading.includes("vision") || heading.includes("objective")) {
      bullets.forEach(b => subGoals.push({ title: b.slice(0, 100), status: "planned", source: heading }));
    } else if (heading.includes("actions taken") || heading.includes("completed")) {
      bullets.forEach(b => actionsTaken.push(b));
    } else if (heading.includes("actions suggested") || heading.includes("recommendations")) {
      bullets.forEach(b => actionsSuggested.push(b));
    } else if (heading.includes("context") || heading.includes("relationship") || heading.includes("track record")) {
      bullets.forEach(b => context.push(b));
    }
  }

  // Determine status
  let status = "tracking";
  if (actionsTaken.length > 0 || subGoals.some(s => s.status === "in-progress")) status = "active";
  if (content.includes("Status: DONE") || content.includes("Status: COMPLETE")) status = "complete";

  return {
    id: path.basename(filepath, ".md"),
    emoji,
    name: cleanName,
    subGoals: subGoals.slice(0, 15),
    actionsTaken: actionsTaken.filter(a => !a.includes("tracking starts")).slice(0, 20),
    actionsSuggested: actionsSuggested.filter(a => !a.includes("none yet")).slice(0, 10),
    context: context.slice(0, 10),
    status,
  };
}

function discoverGoals() {
  try {
    return fs.readdirSync(GOALS_DIR)
      .filter(f => f.endsWith(".md"))
      .map(f => parseGoalFile(path.join(GOALS_DIR, f)))
      .filter(Boolean);
  } catch {
    return [];
  }
}

// ─── Parse memory files for activity feed ───────────────────────────────────

function parseActivityFeed() {
  const activities = [];

  // Check both memory/ root and memory/daily/ for dated files
  for (const dir of [MEMORY_DIR, DAILY_DIR]) {
    try {
      const files = fs.readdirSync(dir)
        .filter(f => f.match(/^\d{4}-\d{2}-\d{2}/) && f.endsWith(".md"))
        .sort()
        .reverse()
        .slice(0, 14);

      for (const file of files) {
        const content = readFile(path.join(dir, file));
        const dateMatch = file.match(/^(\d{4}-\d{2}-\d{2})/);
        const date = dateMatch ? dateMatch[1] : file;

        const sections = content.split(/^## /m).slice(1);
        for (const section of sections) {
          const lines = section.split("\n");
          const title = lines[0].trim();
          
          const desc = lines.slice(1)
            .filter(l => l.trim() && !l.startsWith("#") && !l.startsWith("```") && !l.startsWith("|"))
            .slice(0, 3)
            .map(l => l.replace(/^[-*]\s+/, "").replace(/\*\*/g, "").trim())
            .join(" ")
            .slice(0, 200);

          if (title && desc) {
            activities.push({ date, title: title.slice(0, 100), desc });
          }
        }
      }
    } catch { /* directory may not exist */ }
  }

  return activities.sort((a, b) => b.date.localeCompare(a.date)).slice(0, 100);
}

// ─── Parse MEMORY.md for key facts ──────────────────────────────────────────

function parseKeyFacts() {
  const content = readFile(MEMORY_MD);
  if (!content) return [];

  return content.split(/^## /m).slice(1).map(s => {
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

  const goals = discoverGoals();
  const activities = parseActivityFeed();
  const keyFacts = parseKeyFacts();

  const data = {
    generated: new Date().toISOString(),
    owner: CONFIG.ownerName,
    goals,
    activities,
    keyFacts,
    stats: {
      totalActivities: activities.length,
      totalGoals: goals.length,
      activeGoals: goals.filter(g => g.status === "active").length,
    },
  };

  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, JSON.stringify(data, null, 2));

  // Embed data into index.html for file:// protocol support
  const htmlPath = path.join(path.dirname(OUTPUT), "index.html");
  try {
    let html = fs.readFileSync(htmlPath, "utf-8");
    const dataScript = `<script id="embedded-data">window.__DASHBOARD_DATA__ = ${JSON.stringify(data)};</script>`;
    if (html.includes('<script id="embedded-data">')) {
      html = html.replace(/<script id="embedded-data">[\s\S]*?<\/script>/, dataScript);
    } else {
      html = html.replace('</head>', dataScript + '\n</head>');
    }
    fs.writeFileSync(htmlPath, html);
    console.log("✅ Dashboard data embedded into index.html");
  } catch (e) {
    console.error(`⚠️  Could not embed into index.html: ${e.message}`);
  }

  console.log(`✅ Data written to ${OUTPUT}`);
  console.log(`   Goals: ${goals.length} (${data.stats.activeGoals} active)`);
  console.log(`   Activities: ${activities.length}`);
  console.log(`   Key Facts: ${keyFacts.length}`);
}

main();
