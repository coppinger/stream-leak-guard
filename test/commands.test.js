const { describe, test, expect } = require("bun:test");
const { analyzeCommand, splitCommandParts } = require("../src/commands");

describe("analyzeCommand", () => {
  describe("env command", () => {
    test("blocks bare `env`", () => {
      const result = analyzeCommand("env");
      expect(result.blocked).toBe(true);
    });

    test("allows `env VAR=x command`", () => {
      const result = analyzeCommand("env NODE_ENV=production node app.js");
      expect(result.blocked).toBe(false);
    });
  });

  describe("printenv command", () => {
    test("blocks bare `printenv`", () => {
      const result = analyzeCommand("printenv");
      expect(result.blocked).toBe(true);
    });

    test("allows `printenv HOME`", () => {
      const result = analyzeCommand("printenv HOME");
      expect(result.blocked).toBe(false);
    });
  });

  describe("export command", () => {
    test("blocks `export -p`", () => {
      const result = analyzeCommand("export -p");
      expect(result.blocked).toBe(true);
    });

    test("allows `export VAR=value`", () => {
      const result = analyzeCommand("export NODE_ENV=production");
      expect(result.blocked).toBe(false);
    });
  });

  describe("set command", () => {
    test("blocks bare `set`", () => {
      const result = analyzeCommand("set");
      expect(result.blocked).toBe(true);
    });

    test("allows `set -e`", () => {
      const result = analyzeCommand("set -e");
      expect(result.blocked).toBe(false);
    });
  });

  describe("declare command", () => {
    test("blocks `declare -p` without var", () => {
      const result = analyzeCommand("declare -p");
      expect(result.blocked).toBe(true);
    });

    test("allows `declare -p SPECIFIC_VAR`", () => {
      const result = analyzeCommand("declare -p MY_VAR");
      expect(result.blocked).toBe(false);
    });
  });

  describe("cat/head/tail on .env files", () => {
    test("blocks `cat .env`", () => {
      const result = analyzeCommand("cat .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `cat .env.local`", () => {
      const result = analyzeCommand("cat .env.local");
      expect(result.blocked).toBe(true);
    });

    test("blocks `head .env.production`", () => {
      const result = analyzeCommand("head .env.production");
      expect(result.blocked).toBe(true);
    });

    test("blocks `tail .env`", () => {
      const result = analyzeCommand("tail .env");
      expect(result.blocked).toBe(true);
    });

    test("allows `cat package.json`", () => {
      const result = analyzeCommand("cat package.json");
      expect(result.blocked).toBe(false);
    });
  });

  describe("source .env", () => {
    test("blocks `source .env`", () => {
      const result = analyzeCommand("source .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `. .env`", () => {
      const result = analyzeCommand(". .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `source .env.local`", () => {
      const result = analyzeCommand("source .env.local");
      expect(result.blocked).toBe(true);
    });
  });

  describe("echo/printf with secret vars", () => {
    test("blocks `echo $SECRET_KEY`", () => {
      const result = analyzeCommand("echo $SECRET_KEY");
      expect(result.blocked).toBe(true);
    });

    test("blocks `echo $API_KEY`", () => {
      const result = analyzeCommand("echo $API_KEY");
      expect(result.blocked).toBe(true);
    });

    test("blocks `echo ${PASSWORD}`", () => {
      const result = analyzeCommand("echo ${PASSWORD}");
      expect(result.blocked).toBe(true);
    });

    test("blocks `printf $DATABASE_URL`", () => {
      const result = analyzeCommand("printf $DATABASE_URL");
      expect(result.blocked).toBe(true);
    });

    test("allows `echo hello world`", () => {
      const result = analyzeCommand("echo hello world");
      expect(result.blocked).toBe(false);
    });

    test("allows `echo $HOME`", () => {
      const result = analyzeCommand("echo $HOME");
      expect(result.blocked).toBe(false);
    });
  });

  describe("grep/rg/ag on .env files", () => {
    test("blocks `grep SECRET .env`", () => {
      const result = analyzeCommand("grep SECRET .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `grep SECRET .env.local`", () => {
      const result = analyzeCommand("grep SECRET .env.local");
      expect(result.blocked).toBe(true);
    });

    test("blocks `rg pattern .env`", () => {
      const result = analyzeCommand("rg pattern .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `ag pattern .env.production`", () => {
      const result = analyzeCommand("ag pattern .env.production");
      expect(result.blocked).toBe(true);
    });

    test("allows `grep pattern README.md`", () => {
      const result = analyzeCommand("grep pattern README.md");
      expect(result.blocked).toBe(false);
    });
  });

  describe("awk/sed/cut on .env files", () => {
    test("blocks `awk -F= '{print $2}' .env`", () => {
      const result = analyzeCommand("awk -F= '{print $2}' .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `sed -n '2p' .env.local`", () => {
      const result = analyzeCommand("sed -n '2p' .env.local");
      expect(result.blocked).toBe(true);
    });

    test("blocks `cut -d= -f2 .env`", () => {
      const result = analyzeCommand("cut -d= -f2 .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `sort .env`", () => {
      const result = analyzeCommand("sort .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `strings .env`", () => {
      const result = analyzeCommand("strings .env");
      expect(result.blocked).toBe(true);
    });

    test("allows `awk '{print $1}' data.txt`", () => {
      const result = analyzeCommand("awk '{print $1}' data.txt");
      expect(result.blocked).toBe(false);
    });
  });

  describe("inline code execution targeting .env", () => {
    test("blocks `node -e` reading .env", () => {
      const result = analyzeCommand('node -e "require(\'fs\').readFileSync(\'.env\')"');
      expect(result.blocked).toBe(true);
    });

    test("blocks `python -c` reading .env", () => {
      const result = analyzeCommand("python -c \"open('.env').read()\"");
      expect(result.blocked).toBe(true);
    });

    test("blocks `python3 -c` reading .env", () => {
      const result = analyzeCommand("python3 -c \"open('.env').read()\"");
      expect(result.blocked).toBe(true);
    });

    test("blocks `ruby -e` reading .env", () => {
      const result = analyzeCommand("ruby -e \"File.read('.env')\"");
      expect(result.blocked).toBe(true);
    });

    test("allows `node -e` without .env", () => {
      const result = analyzeCommand("node -e \"console.log('hello')\"");
      expect(result.blocked).toBe(false);
    });
  });

  describe("generic catch-all for .env file arguments", () => {
    test("blocks `cp .env /tmp/`", () => {
      const result = analyzeCommand("cp .env /tmp/");
      expect(result.blocked).toBe(true);
    });

    test("blocks `diff .env .env.bak`", () => {
      const result = analyzeCommand("diff .env .env.bak");
      expect(result.blocked).toBe(true);
    });

    test("blocks `xxd .env`", () => {
      const result = analyzeCommand("xxd .env");
      expect(result.blocked).toBe(true);
    });

    test("blocks `mv .env.local /tmp/`", () => {
      const result = analyzeCommand("mv .env.local /tmp/");
      expect(result.blocked).toBe(true);
    });

    test("blocks commands with path to .env", () => {
      const result = analyzeCommand("cp /home/user/project/.env /tmp/");
      expect(result.blocked).toBe(true);
    });

    test("allows commands with no .env args", () => {
      const result = analyzeCommand("cp file.txt /tmp/");
      expect(result.blocked).toBe(false);
    });
  });

  describe("compound commands", () => {
    test("blocks dangerous command in pipe", () => {
      const result = analyzeCommand("echo hello | env");
      expect(result.blocked).toBe(true);
    });

    test("blocks dangerous command after &&", () => {
      const result = analyzeCommand("cd /tmp && env");
      expect(result.blocked).toBe(true);
    });

    test("blocks dangerous command in subshell", () => {
      const result = analyzeCommand("echo $(env)");
      expect(result.blocked).toBe(true);
    });

    test("blocks dangerous command in backticks", () => {
      const result = analyzeCommand("echo `printenv`");
      expect(result.blocked).toBe(true);
    });

    test("allows safe compound commands", () => {
      const result = analyzeCommand("npm install && npm test");
      expect(result.blocked).toBe(false);
    });
  });

  describe("allowlist", () => {
    test("allows command on allowlist", () => {
      const result = analyzeCommand("env", ["env"]);
      expect(result.blocked).toBe(false);
    });

    test("allows command starting with allowlisted prefix", () => {
      const result = analyzeCommand("cat .env.example", ["cat .env.example"]);
      expect(result.blocked).toBe(false);
    });
  });

  describe("edge cases", () => {
    test("handles empty command", () => {
      const result = analyzeCommand("");
      expect(result.blocked).toBe(false);
    });

    test("handles null command", () => {
      const result = analyzeCommand(null);
      expect(result.blocked).toBe(false);
    });

    test("allows normal commands", () => {
      expect(analyzeCommand("npm test").blocked).toBe(false);
      expect(analyzeCommand("ls -la").blocked).toBe(false);
      expect(analyzeCommand("git status").blocked).toBe(false);
      expect(analyzeCommand("node app.js").blocked).toBe(false);
    });
  });
});

describe("splitCommandParts", () => {
  test("splits on &&", () => {
    const parts = splitCommandParts("a && b");
    expect(parts).toContain("a");
    expect(parts).toContain("b");
  });

  test("splits on ||", () => {
    const parts = splitCommandParts("a || b");
    expect(parts).toContain("a");
    expect(parts).toContain("b");
  });

  test("splits on ;", () => {
    const parts = splitCommandParts("a ; b");
    expect(parts).toContain("a");
    expect(parts).toContain("b");
  });

  test("extracts subshell contents", () => {
    const parts = splitCommandParts("echo $(whoami)");
    expect(parts).toContain("whoami");
  });

  test("extracts backtick contents", () => {
    const parts = splitCommandParts("echo `date`");
    expect(parts).toContain("date");
  });
});
