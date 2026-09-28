import { Button, Input, Textarea } from "./ui";
import { useState } from "react";

export type EnvRow = { key: string; value: string };

export function parseDotenv(text: string): EnvRow[] {
  const out: EnvRow[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    out.push({ key: m[1], value: v });
  }
  return out;
}

export function EnvEditor({ rows, onChange }: { rows: EnvRow[]; onChange: (r: EnvRow[]) => void }) {
  const [paste, setPaste] = useState(false);
  const [text, setText] = useState("");
  const set = (i: number, r: Partial<EnvRow>) => onChange(rows.map((x, j) => (i === j ? { ...x, ...r } : x)));
  return (
    <div className="space-y-2">
      {rows.map((r, i) => (
        <div key={i} className="flex gap-2">
          <Input placeholder="NAME" value={r.key} onChange={(e) => set(i, { key: e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_") })} className="font-mono" />
          <Input placeholder="value" type="password" autoComplete="off" value={r.value} onChange={(e) => set(i, { value: e.target.value })} className="font-mono" />
          <Button variant="ghost" type="button" onClick={() => onChange(rows.filter((_, j) => j !== i))} aria-label="Remove">
            ✕
          </Button>
        </div>
      ))}
      {paste && (
        <div className="space-y-2">
          <Textarea rows={5} placeholder={"KEY=value\nOTHER=value"} value={text} onChange={(e) => setText(e.target.value)} />
          <Button
            type="button"
            size="sm"
            onClick={() => {
              onChange([...rows.filter((r) => r.key), ...parseDotenv(text)]);
              setText("");
              setPaste(false);
            }}
          >
            Add variables
          </Button>
        </div>
      )}
      <div className="flex gap-2">
        <Button type="button" size="sm" onClick={() => onChange([...rows, { key: "", value: "" }])}>
          Add variable
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => setPaste(!paste)}>
          Paste .env
        </Button>
      </div>
    </div>
  );
}
