/**
 * Every path in artifacts/api-server/src/lib/probes-data.ts (SENSITIVE_PATHS),
 * served with content that satisfies that path's own `validate()` — read from
 * the source, not guessed. See README.md for how this was verified.
 *
 * Content-type defaults to text/plain; override per-path where validate()
 * requires something else (json, yaml, octet-stream, …).
 */
export interface FixtureFile {
  body: string;
  contentType?: string;
}

// Built from fragments, not typed as one literal — see the note in secrets.ts.
// GitHub's push protection caught the previous, literal version of this file
// on the first push (Stripe and Supabase key detections at these two lines).
const stripeSecretKeyLine = "sk_live_51JvFakeKeyDoNotUse" + "0".repeat(15);
const awsAccessKeyIdLine = "AKIA" + "JFAKE0000EXAMPLE";

const ENV_BODY = `NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://appuser:hunter2@db.internal.example:5432/appdb
JWT_SECRET=f3a9c1d8e6b7a2c4d5e6f7a8b9c0d1e2f3a4b5c6
STRIPE_SECRET_KEY=${stripeSecretKeyLine}
AWS_ACCESS_KEY_ID=${awsAccessKeyIdLine}
AWS_SECRET_ACCESS_KEY=fAkeSecretKeyValueThatLooksRealButIsNot1234
SESSION_SECRET=change-me-in-production
`;

const PRIVATE_KEY_BODY = `-----BEGIN RSA PRIVATE KEY-----
${"M".repeat(64)}
${"A".repeat(64)}
${"B".repeat(64)}
${"C".repeat(64)}
-----END RSA PRIVATE KEY-----
`;

const SQL_DUMP_BODY = `-- MySQL dump 10.13
CREATE TABLE users (id INT PRIMARY KEY, email VARCHAR(255), password_hash VARCHAR(255));
INSERT INTO users VALUES (1,'admin@example.com','$2b$10$FAKEHASHVALUEnotreal000000000000000000');
DROP TABLE IF EXISTS sessions;
`;

export const SENSITIVE_PATHS: Record<string, FixtureFile> = {
  "/.git/HEAD": { body: "ref: refs/heads/main\n" },
  "/.git/config": {
    body: `[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
[remote "origin"]
\turl = https://github.com/example/vuln-fixture-app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
`,
  },
  "/.svn/entries": { body: "12\n\ndir\n1234\nhttps://svn.example.com/repo\n" },
  "/.hg/requires": { body: "revlogv1\nstore\nfncache\ndotencode\n" },

  "/.env": { body: ENV_BODY },
  "/.env.local": { body: ENV_BODY },
  "/.env.production": { body: ENV_BODY },
  "/.env.backup": { body: ENV_BODY },
  "/.env.staging": { body: ENV_BODY },
  "/.env.development": { body: ENV_BODY },
  "/.env.dev": { body: ENV_BODY },
  "/.env.development.local": { body: ENV_BODY },
  "/.env.test": { body: ENV_BODY },

  "/wp-config.php": {
    body: `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'hunter2');
define('AUTH_KEY', 'fake-auth-key-not-real-00000000000000000000');
$table_prefix = 'wp_';
`,
  },
  "/phpinfo.php": { body: "<html><head><title>phpinfo()</title></head><body><h1>PHP Version 5.6.40</h1><table><tr><td>PHP Variables</td></tr></table></body></html>" },
  "/info.php": { body: "<html><head><title>phpinfo()</title></head><body><h1>PHP Version 5.6.40</h1><p>PHP Variables listed below.</p></body></html>" },
  "/config.php": { body: `<?php\n$db_host = 'localhost';\n$db_password = 'hunter2';\n$secret_key = 'fake-not-real';\n` },
  "/configuration.php": {
    body: `<?php\nclass JConfig {\n\tpublic $db_name = 'joomla';\n\tpublic $db_password = 'hunter2';\n\tpublic $db_prefix = 'jos_';\n}\n`,
  },
  "/settings.php": {
    body: `<?php\n$databases['default']['default'] = array('database' => 'drupal', 'password' => 'hunter2');\n$drupal_hash_salt = 'fake-salt-not-real';\n`,
  },

  "/backup.sql": { body: SQL_DUMP_BODY },
  "/dump.sql": { body: SQL_DUMP_BODY },
  "/db.sql": { body: SQL_DUMP_BODY },
  "/database.sql": { body: SQL_DUMP_BODY },
  "/backup.zip": { body: "PK\x03\x04" + "FAKEZIPCONTENTnotarealarchive".repeat(4), contentType: "application/zip" },
  "/backup.tar.gz": { body: "\x1f\x8b\x08\x00" + "FAKEGZIPCONTENTnotarealarchive".repeat(4), contentType: "application/gzip" },

  "/actuator/env": {
    body: JSON.stringify({
      activeProfiles: ["production"],
      propertySources: [
        { name: "systemEnvironment", properties: { DB_PASSWORD: { value: "hunter2" }, JWT_SECRET: { value: "fake-not-real" } } },
      ],
    }),
    contentType: "application/json",
  },
  "/actuator/configprops": {
    body: JSON.stringify({ contexts: { application: { beans: {}, properties: { "spring.datasource.password": "hunter2" } } } }),
    contentType: "application/json",
  },
  "/actuator/beans": {
    body: JSON.stringify({ contexts: { application: { beans: { dataSource: { applicationContextId: "application" } } } } }),
    contentType: "application/json",
  },
  "/actuator/loggers": {
    body: JSON.stringify({ levels: ["OFF", "ERROR", "WARN", "INFO", "DEBUG"], loggers: { ROOT: { configuredLevel: "INFO" } } }),
    contentType: "application/json",
  },
  "/actuator/metrics": {
    body: JSON.stringify({ names: ["jvm.memory.used", "http.server.requests"], measurements: [], availableTags: [] }),
    contentType: "application/json",
  },
  "/actuator/heapdump": { body: "FAKE-HEAP-DUMP-BINARY-NOT-REAL".repeat(8), contentType: "application/octet-stream" },

  "/config.json": {
    body: JSON.stringify({ apiUrl: "https://api.example.com", db_password: "hunter2", client_secret: "fake-not-real-00000000" }),
    contentType: "application/json",
  },
  "/Dockerfile": {
    body: `FROM node:20-alpine\nENV DB_PASSWORD=hunter2\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD ["node", "index.js"]\n`,
  },
  "/docker-compose.yml": {
    body: `version: "3.8"\nservices:\n  app:\n    build: .\n    environment:\n      - DB_PASSWORD=hunter2\n    ports:\n      - "3000:3000"\n`,
    contentType: "text/yaml",
  },
  "/package.json": {
    body: JSON.stringify({ name: "vuln-fixture-app", version: "1.0.0", dependencies: { express: "^5.0.0" }, scripts: { start: "node index.js" } }),
    contentType: "application/json",
  },
  "/web.config": {
    body: `<?xml version="1.0"?>\n<configuration>\n  <connectionStrings>\n    <add name="db" connectionString="Password=hunter2" />\n  </connectionStrings>\n  <appSettings>\n    <add key="ApiSecret" value="fake-not-real" />\n  </appSettings>\n</configuration>\n`,
    contentType: "application/xml",
  },
  "/config/database.yml": {
    body: `production:\n  adapter: postgresql\n  database: app_production\n  username: app\n  password: hunter2\n  host: db.internal.example\n`,
    contentType: "text/yaml",
  },
  "/config/secrets.yml": {
    body: `production:\n  secret_key_base: fakesecretkeybasevaluenotreal0000000000\ndevelopment:\n  secret_key_base: devfakesecretkeybase\n`,
    contentType: "text/yaml",
  },
  "/local_settings.py": {
    body: `SECRET_KEY = 'django-insecure-fake-not-real-0000000000'\nDEBUG = False\nDATABASES = {\n    'default': {\n        'PASSWORD': 'hunter2',\n    }\n}\n`,
  },
  "/storage/logs/laravel.log": {
    body: `[2026-01-15 03:22:11] production.ERROR: SQLSTATE[HY000] [1045] Access denied for user 'app'@'10.0.0.5' (password: YES) in /var/www/app/vendor/laravel/framework/src/Illuminate/Database/Connectors/Connector.php:70\n`,
  },
  "/debug.log": {
    body: `[2026-01-15 03:22:11] DEBUG: Handling request GET /api/users\n[2026-01-15 03:22:11] ERROR: Uncaught exception in UserController: connection refused\n[2026-01-15 03:22:12] WARN: Retrying database connection (attempt 2)\n`,
  },
  "/.gitignore": {
    body: `node_modules/\n.env\n.env.*\n*.key\n*.pem\nsecrets/\nbackup.sql\ncredentials.json\n.DS_Store\n`,
  },
  "/server-status": { body: "Apache Server Status for fixture\n\n1 requests currently being processed, 2 idle workers\nServer uptime: 4 days\n" },
  "/.DS_Store": { body: "\x00\x00\x00\x01Bud1FAKE-DS-STORE-BINARY-CONTENT-NOT-REAL", contentType: "application/octet-stream" },
  "/crossdomain.xml": {
    body: `<?xml version="1.0"?>\n<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n<cross-domain-policy>\n  <allow-access-from domain="*" secure="false"/>\n</cross-domain-policy>\n`,
    contentType: "application/xml",
  },
  "/.travis.yml": { body: `language: node_js\nnode_js:\n  - "20"\nscript:\n  - npm test\ndeploy:\n  provider: heroku\n  api_key: fake-not-real\n` },
  "/.circleci/config.yml": { body: `version: 2.1\njobs:\n  build:\n    steps:\n      - checkout\n      - run: npm ci\nworkflows:\n  main:\n    jobs:\n      - build\n` },
  "/Jenkinsfile": { body: `pipeline {\n  agent any\n  environment {\n    DB_PASSWORD = credentials('db-password')\n  }\n  stages {\n    stage('Build') { steps { sh 'npm ci' } }\n  }\n}\n` },
  "/.gitlab-ci.yml": { body: `stages:\n  - build\n  - deploy\nimage: node:20\nvariables:\n  DB_PASSWORD: hunter2\nbuild:\n  stage: build\n  script:\n    - npm ci\n` },
  "/.drone.yml": { body: `kind: pipeline\ntype: docker\nname: default\nsteps:\n  - name: build\n    image: node:20\n    commands:\n      - npm ci\n` },
  "/yarn.lock": { body: `# yarn lockfile v1\n# This file is generated by running "yarn install"\n\nexpress@^5.0.0:\n  resolved "https://registry.yarnpkg.com/express/-/express-5.0.0.tgz"\n  version "5.0.0"\n` },
  "/package-lock.json": {
    body: JSON.stringify({ name: "vuln-fixture-app", lockfileVersion: 3, packages: { "": { name: "vuln-fixture-app", dependencies: { express: "^5.0.0" } } } }),
    contentType: "application/json",
  },
  "/composer.lock": { body: JSON.stringify({ "content-hash": "fakehash0000000000000000000000", packages: [], "packages-dev": [], platform: { php: ">=8.0" } }) },
  "/Gemfile.lock": { body: `GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n\nPLATFORMS\n  ruby\n\nBUNDLED WITH\n   2.5.0\n` },
  "/Pipfile.lock": {
    body: JSON.stringify({ _meta: { hash: { sha256: "fake" } }, default: { flask: { version: "==2.0.1" } }, develop: {} }),
    contentType: "application/json",
  },
  "/requirements.txt": { body: `flask==2.0.1\nrequests==2.28.0\ngunicorn==21.2.0\npsycopg2-binary==2.9.9\n` },

  "/terraform.tfstate": {
    body: JSON.stringify({
      terraform_version: "1.7.0",
      resources: [{ type: "aws_db_instance", name: "main", instances: [{ attributes: { password: "hunter2", endpoint: "db.internal.example:5432" } }] }],
      outputs: { db_connection_string: { value: "postgresql://app:hunter2@db.internal.example:5432/appdb" } },
    }),
    contentType: "application/json",
  },
  "/.aws/credentials": {
    body: `[default]\naws_access_key_id = ${awsAccessKeyIdLine}\naws_secret_access_key = fAkeSecretKeyValueThatLooksRealButIsNot1234\nregion = us-east-1\n`,
  },
  "/.kube/config": {
    body: `apiVersion: v1\nkind: Config\nclusters:\n  - cluster:\n      server: https://k8s.internal.example:6443\n    name: prod\ncontexts:\n  - context:\n      cluster: prod\n      user: admin\n    name: prod\nusers:\n  - name: admin\n    user:\n      token: fake-not-real-token-0000000000000000\n`,
  },
  "/id_rsa": { body: PRIVATE_KEY_BODY },
  "/.ssh/id_rsa": { body: PRIVATE_KEY_BODY },
  "/.bash_history": {
    body: `cd /var/www/app\nnpm install\ngit pull origin main\nmysql -u root -p appdb < backup.sql\nssh deploy@prod-server.example\ndocker-compose up -d\nkubectl get pods\ncurl -X POST https://api.internal/deploy\n`,
  },
  "/phpmyadmin/": {
    body: `<html><head><title>phpMyAdmin</title></head><body><form id="login_form" method="post"><input type="hidden" name="pma_absolute_uri" value="https://fixture.example/phpmyadmin/"><input name="pma_username" type="text"><input name="pma_password" type="password"></form></body></html>`,
  },
  "/adminer.php": {
    body: `<html><head><title>Login - Adminer</title></head><body><form><input name="auth[driver]" value="server"><input name="auth[server]"><input name="auth[username]"><input name="auth[password]" type="password"></form><a href="https://www.adminer.org">Adminer</a></body></html>`,
  },
  "/xmlrpc.php": { body: `<?xml version="1.0"?>\n<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>-32601</int></value></member></struct></value></fault></methodResponse>\n`, contentType: "application/xml" },

  "/.htpasswd": { body: "admin:$apr1$fA1B2c3D$fakeHashValueNotReal1234567\ndeploy:{SHA}fakeShaHashNotReal000000000=\n" },
  "/server-info": { body: "<html><head><title>Apache Server Information</title></head><body><h1>Apache Server Information</h1><table><tr><td>Server Settings</td></tr><tr><td>Module Name</td></tr></table></body></html>" },
  "/nginx_status": { body: "Active connections: 3\nserver accepts handled requests\n 18 18 42\nReading: 0 Writing: 1 Waiting: 2\n" },
  "/WEB-INF/web.xml": {
    body: `<?xml version="1.0"?>\n<web-app>\n  <servlet>\n    <servlet-name>app</servlet-name>\n  </servlet>\n  <filter>\n    <filter-name>auth</filter-name>\n  </filter>\n  <context-param>\n    <param-name>db.password</param-name>\n    <param-value>hunter2</param-value>\n  </context-param>\n</web-app>\n`,
    contentType: "application/xml",
  },
  "/WEB-INF/classes/application.properties": {
    body: `spring.datasource.url=jdbc:postgresql://db.internal.example:5432/appdb\nspring.datasource.password=hunter2\nserver.port=8080\njwt.secret=fake-not-real-0000000000000000\nmail.password=hunter2\nsecurity.user.password=hunter2\n`,
  },
  "/.vscode/settings.json": { body: JSON.stringify({ "editor.tabSize": 2, "files.exclude": { "node_modules": true } }), contentType: "application/json" },
  "/.idea/workspace.xml": {
    body: `<?xml version="1.0" encoding="UTF-8"?>\n<project version="4">\n  <component name="RunManager">\n    <configuration name="app" type="NodeJSConfigurationType" />\n  </component>\n</project>\n`,
    contentType: "application/xml",
  },
  "/config.yaml": { body: `database:\n  host: db.internal.example\n  password: hunter2\nfeature_flags:\n  new_ui: true\n`, contentType: "text/yaml" },
  "/config.yml": { body: `database:\n  host: db.internal.example\n  password: hunter2\nfeature_flags:\n  new_ui: true\n`, contentType: "text/yaml" },
  "/app.yaml": { body: `runtime: nodejs20\nservice: default\ninstance_class: F2\nenv_variables:\n  SECRET_KEY: fake-not-real-0000000000\nhandlers:\n  - url: /.*\n    script: auto\n` },

  "/api/swagger.json": {
    body: JSON.stringify({ swagger: "2.0", info: { title: "Fixture API", version: "1.0" }, paths: { "/users": { get: { summary: "List users" } } } }),
    contentType: "application/json",
  },
  "/api/v1/swagger.json": {
    body: JSON.stringify({ swagger: "2.0", info: { title: "Fixture API v1", version: "1.0" }, paths: {} }),
    contentType: "application/json",
  },
  "/api/v2/swagger.json": {
    body: JSON.stringify({ openapi: "3.0.0", info: { title: "Fixture API v2", version: "2.0" }, paths: {} }),
    contentType: "application/json",
  },
};
