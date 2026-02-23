#!/usr/bin/env node
/**
 * Relationships CRM CLI
 * Manage contacts for OpenClaw agent memory
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, appendFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MEMORY_ROOT = join(__dirname, '../../..', 'memory/relationships');
const INDEX_PATH = join(MEMORY_ROOT, 'index.json');

const CATEGORIES = ['family', 'close_friends', 'church_friends', 'colleagues', 'broader_community', 'strangers', 'bad_actors', 'unknown'];

function loadIndex() {
  if (!existsSync(INDEX_PATH)) {
    return { version: '1.0.0', lastUpdated: new Date().toISOString().split('T')[0], categories: {}, contacts: [] };
  }
  return JSON.parse(readFileSync(INDEX_PATH, 'utf-8'));
}

function saveIndex(index) {
  index.lastUpdated = new Date().toISOString().split('T')[0];
  writeFileSync(INDEX_PATH, JSON.stringify(index, null, 2));
}

function createContact(name, category, options = {}) {
  const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
  const categoryDir = join(MEMORY_ROOT, category);

  if (!existsSync(categoryDir)) {
    mkdirSync(categoryDir, { recursive: true });
  }

  const filePath = join(categoryDir, `${slug}.md`);

  const content = `# ${name}

## Basics
- **Category:** ${category}
- **Relationship:** ${options.relationship || 'TBD'}
- **First met:** ${options.firstMet || 'TBD'}
- **Last contact:** ${new Date().toISOString().split('T')[0]}

## Context
${options.context || 'To be filled in.'}

## Key Details
${options.birthday ? `- Birthday: ${options.birthday}` : ''}
${options.location ? `- Location: ${options.location}` : ''}
${options.phone ? `- Phone: ${options.phone}` : ''}
${options.email ? `- Email: ${options.email}` : ''}
${options.social ? `- Social: ${options.social}` : ''}
${options.organization ? `- Organization: ${options.organization}` : ''}

## Family
${options.family || 'TBD'}

## Interactions

## Notes
`;

  writeFileSync(filePath, content);

  // Update index
  const index = loadIndex();
  const existing = index.contacts.find(c => c.name.toLowerCase() === name.toLowerCase());
  if (existing) {
    existing.category = category;
    existing.file = `${category}/${slug}.md`;
  } else {
    index.contacts.push({
      name,
      category,
      relationship: options.relationship || 'TBD',
      file: `${category}/${slug}.md`
    });
  }

  // Update category counts
  index.categories = {};
  for (const cat of CATEGORIES) {
    index.categories[cat] = index.contacts.filter(c => c.category === cat).length;
  }

  saveIndex(index);
  console.log(JSON.stringify({ success: true, name, category, file: `${category}/${slug}.md` }, null, 2));
}

function listCategory(category) {
  const index = loadIndex();
  const contacts = index.contacts.filter(c => c.category === category);
  console.log(JSON.stringify(contacts, null, 2));
}

function searchContacts(query) {
  const index = loadIndex();
  const results = [];

  for (const contact of index.contacts) {
    const filePath = join(MEMORY_ROOT, contact.file);
    if (existsSync(filePath)) {
      const content = readFileSync(filePath, 'utf-8').toLowerCase();
      if (content.includes(query.toLowerCase()) || contact.name.toLowerCase().includes(query.toLowerCase())) {
        results.push({
          ...contact,
          snippet: content.split('\n').find(line => line.toLowerCase().includes(query.toLowerCase()))?.trim() || ''
        });
      }
    }
  }

  console.log(JSON.stringify(results, null, 2));
}

function logInteraction(name, date, summary) {
  const index = loadIndex();
  const contact = index.contacts.find(c => c.name.toLowerCase().includes(name.toLowerCase()));

  if (!contact) {
    console.error(JSON.stringify({ error: 'Contact not found', name }));
    process.exit(1);
  }

  const filePath = join(MEMORY_ROOT, contact.file);
  let content = readFileSync(filePath, 'utf-8');

  const interaction = `\n### ${date} - Interaction\n${summary}\n`;

  // Insert before Notes section or at end
  if (content.includes('## Notes')) {
    content = content.replace('## Notes', interaction + '\n## Notes');
  } else {
    content += interaction;
  }

  // Update last contact
  content = content.replace(/- \*\*Last contact:\*\* .*/, `- **Last contact:** ${date}`);

  writeFileSync(filePath, content);

  console.log(JSON.stringify({ success: true, name: contact.name, date, summary }));
}

function updateContact(name, field, value) {
  const index = loadIndex();
  const contact = index.contacts.find(c => c.name.toLowerCase().includes(name.toLowerCase()));

  if (!contact) {
    console.error(JSON.stringify({ error: 'Contact not found', name }));
    process.exit(1);
  }

  const filePath = join(MEMORY_ROOT, contact.file);
  let content = readFileSync(filePath, 'utf-8');

  const fieldMap = {
    'category': (v) => {
      // Move file to new category
      const oldPath = filePath;
      const newDir = join(MEMORY_ROOT, v);
      if (!existsSync(newDir)) mkdirSync(newDir, { recursive: true });
      const newPath = join(newDir, contact.file.split('/')[1]);
      // Would need fs.rename here, simplified for now
      return content;
    },
    'relationship': (v) => {
      contact.relationship = v;
      return content.replace(/- \*\*Relationship:\*\* .*/, `- **Relationship:** ${v}`);
    },
    'birthday': (v) => content.includes('Birthday:')
      ? content.replace(/- Birthday: .*/, `- Birthday: ${v}`)
      : content.replace('## Key Details', `## Key Details\n- Birthday: ${v}`),
    'location': (v) => content.includes('Location:')
      ? content.replace(/- Location: .*/, `- Location: ${v}`)
      : content.replace('## Key Details', `## Key Details\n- Location: ${v}`),
    'phone': (v) => content.includes('Phone:')
      ? content.replace(/- Phone: .*/, `- Phone: ${v}`)
      : content.replace('## Key Details', `## Key Details\n- Phone: ${v}`),
    'email': (v) => content.includes('Email:')
      ? content.replace(/- Email: .*/, `- Email: ${v}`)
      : content.replace('## Key Details', `## Key Details\n- Email: ${v}`),
    'social': (v) => content.includes('Social:')
      ? content.replace(/- Social: .*/, `- Social: ${v}`)
      : content.replace('## Key Details', `## Key Details\n- Social: ${v}`),
    'organization': (v) => content.includes('Organization:')
      ? content.replace(/- Organization: .*/, `- Organization: ${v}`)
      : content.replace('## Key Details', `## Key Details\n- Organization: ${v}`),
    'context': (v) => content.replace(/## Context\n[\s\S]*?\n##/, `## Context\n${v}\n\n##`),
  };

  if (fieldMap[field]) {
    content = fieldMap[field](value);
    writeFileSync(filePath, content);
    saveIndex(index);
    console.log(JSON.stringify({ success: true, name: contact.name, field, value }));
  } else {
    console.error(JSON.stringify({ error: 'Unknown field', field }));
    process.exit(1);
  }
}

function summary() {
  const index = loadIndex();
  const now = new Date();
  const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
  const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const ninetyDaysAgo = new Date(now - 90 * 24 * 60 * 60 * 1000);

  const stats = {
    total: index.contacts.length,
    byCategory: {},
    recentInteractions: [],
    upcomingBirthdays: [],
    staleContacts: []
  };

  // Category counts
  for (const cat of CATEGORIES) {
    stats.byCategory[cat] = index.contacts.filter(c => c.category === cat).length;
  }

  // Scan contacts for interactions, birthdays, staleness
  for (const contact of index.contacts) {
    const filePath = join(MEMORY_ROOT, contact.file);
    if (!existsSync(filePath)) continue;

    const content = readFileSync(filePath, 'utf-8');

    // Check last contact
    const lastContactMatch = content.match(/\*\*Last contact:\*\* (\d{4}-\d{2}-\d{2})/);
    if (lastContactMatch) {
      const lastContact = new Date(lastContactMatch[1]);
      if (lastContact < ninetyDaysAgo) {
        stats.staleContacts.push({
          name: contact.name,
          category: contact.category,
          lastContact: lastContactMatch[1]
        });
      }
    }

    // Check for birthday
    const birthdayMatch = content.match(/Birthday: (\d{4}-\d{2}-\d{2})/);
    if (birthdayMatch) {
      const birthday = new Date(birthdayMatch[1]);
      const thisYearBirthday = new Date(now.getFullYear(), birthday.getMonth(), birthday.getDate());
      if (thisYearBirthday >= now && thisYearBirthday <= thirtyDaysFromNow) {
        stats.upcomingBirthdays.push({
          name: contact.name,
          birthday: birthdayMatch[1],
          daysUntil: Math.ceil((thisYearBirthday - now) / (24 * 60 * 60 * 1000))
        });
      }
    }
  }

  console.log(JSON.stringify(stats, null, 2));
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'add': {
      const name = args[1];
      const category = args.includes('--category') ? args[args.indexOf('--category') + 1] : 'unknown';
      const options = {
        relationship: args.includes('--relationship') ? args[args.indexOf('--relationship') + 1] : undefined,
        context: args.includes('--context') ? args[args.indexOf('--context') + 1] : undefined,
        birthday: args.includes('--birthday') ? args[args.indexOf('--birthday') + 1] : undefined,
        location: args.includes('--location') ? args[args.indexOf('--location') + 1] : undefined,
        email: args.includes('--email') ? args[args.indexOf('--email') + 1] : undefined,
        phone: args.includes('--phone') ? args[args.indexOf('--phone') + 1] : undefined,
        social: args.includes('--social') ? args[args.indexOf('--social') + 1] : undefined,
        organization: args.includes('--organization') ? args[args.indexOf('--organization') + 1] : undefined,
      };
      createContact(name, category, options);
      break;
    }
    case 'list': {
      listCategory(args[1]);
      break;
    }
    case 'search': {
      searchContacts(args[1]);
      break;
    }
    case 'interact': {
      const name = args[1];
      const date = args.includes('--date') ? args[args.indexOf('--date') + 1] : new Date().toISOString().split('T')[0];
      const summary = args.includes('--summary') ? args[args.indexOf('--summary') + 1] : args.slice(args.indexOf('--summary') + 1).join(' ');
      logInteraction(name, date, summary);
      break;
    }
    case 'update': {
      const name = args[1];
      const field = args.includes('--field') ? args[args.indexOf('--field') + 1] : undefined;
      const value = args.includes('--value') ? args[args.indexOf('--value') + 1] : undefined;
      updateContact(name, field, value);
      break;
    }
    case 'summary': {
      summary();
      break;
    }
    default:
      console.error('Usage: relationship.mjs <add|list|search|interact|update|summary>');
      process.exit(1);
  }
}

main();