/** Prints what the GitHub source scan did for each repo: outcome, files read, findings. */
import { scanGithubRepo, parseGithubRepoRef } from "../src/lib/githubSourceProbe.js";

for (const input of process.argv.slice(2)) {
  const ref = parseGithubRepoRef(input);
  if (!ref) {
    console.log(`${input}: not a repository reference`);
    continue;
  }
  const out = await scanGithubRepo(ref);
  console.log(
    `${ref.owner}/${ref.repo}: ${out.status}` +
      ("filesRead" in out ? `, files read ${out.filesRead}` : "") +
      `, findings ${out.findings?.length ?? 0}`,
  );
  for (const f of out.findings ?? []) console.log(`   ${f.name}`);
}
