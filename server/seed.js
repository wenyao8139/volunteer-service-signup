import fs from "node:fs/promises";
import cloudbase from "@cloudbase/node-sdk";

if (!process.env.CLOUDBASE_ENV_ID) {
  throw new Error("Missing required environment variable: CLOUDBASE_ENV_ID");
}

const cloud = cloudbase.init({ env: process.env.CLOUDBASE_ENV_ID });
const activities = cloud.database().collection("activities");
const source = new URL("./seed-data.json", import.meta.url);
const records = JSON.parse(await fs.readFile(source, "utf8"));
const timestamp = new Date().toISOString();

for (const record of records) {
  const { _id, ...data } = record;
  const result = await activities.doc(_id).get();
  const exists = Array.isArray(result?.data) ? result.data.length > 0 : Boolean(result?.data);
  if (exists) {
    console.log(`Skipped existing activity: ${_id}`);
    continue;
  }
  await activities.doc(_id).set({
    ...data,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  console.log(`Created activity: ${_id}`);
}

console.log("Seed complete.");
