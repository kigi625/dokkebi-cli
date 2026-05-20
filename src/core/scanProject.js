import fs from 'fs/promises';
import path from 'path';

const BACKEND_CANDIDATES = ['backend', 'server', 'api', 'back'];
const FRONTEND_CANDIDATES = ['frontend', 'web', 'client', 'app', 'front'];

async function pathExists(targetPath) {
    try {
        await fs.access(targetPath);
        return true;
    } catch {
        return false;
    }
}

async function isDirectory(targetPath) {
    try {
        const stat = await fs.stat(targetPath);
        return stat.isDirectory();
    } catch {
        return false;
    }
}

async function readPackageJson(rootDir) {
    const packagePath = path.join(rootDir, 'package.json');
    if (!(await pathExists(packagePath))) {
        return { packagePath: null, packageJson: null, dependencies: {} };
    }
    const raw = await fs.readFile(packagePath, 'utf8');
    const parsed = JSON.parse(raw);
    const dependencies = {
        ...(parsed.dependencies || {}),
        ...(parsed.devDependencies || {}),
    };
    return { packagePath, packageJson: parsed, dependencies };
}

async function detectByCandidate(rootDir, candidates) {
    for (const candidate of candidates) {
        const resolved = path.resolve(rootDir, candidate);
        if (await isDirectory(resolved)) return resolved;
    }
    return null;
}

function hasExpress(dependencies) {
    return Boolean(
        (dependencies && dependencies.express) ||
        (dependencies && dependencies['express']) ||
        (dependencies && dependencies['@express/core'])
    );
}

function hasVue(dependencies) {
    return Boolean(
        dependencies?.vue ||
        dependencies?.['@vue/core'] ||
        dependencies?.['nuxt']
    );
}

function hasReact(dependencies) {
    return Boolean(
        dependencies?.react ||
        dependencies?.['react-dom']
    );
}

async function detectBackendEntry(backendDir) {
    const entries = ['index.js', 'app.js', 'server.js', 'main.js', 'src/index.js', 'src/app.js', 'src/server.js'];
    for (const entry of entries) {
        const resolved = path.join(backendDir, entry);
        if (await pathExists(resolved)) return resolved;
    }
    return null;
}

async function detectFrontendBuildCommand(packageJson) {
    const scripts = packageJson?.scripts || {};
    if (scripts.build) return 'npm run build';
    if (scripts['build:prod']) return 'npm run build:prod';
    return null;
}

async function detectFrontendDistDir(frontendDir, packageJson) {
    const distFromVite = path.join(frontendDir, 'dist');
    const distFromVue = path.join(frontendDir, 'dist');
    const distFromReact = path.join(frontendDir, 'dist');
    const outFromNuxt = path.join(frontendDir, '.output', 'public');
    if (await pathExists(distFromVite)) return 'dist';
    if (await pathExists(outFromNuxt)) return '.output/public';
    return 'dist';
}

async function detectBackendFallback(rootDir) {
    const routesPath = path.join(rootDir, 'routes');
    const appJsPath = path.join(rootDir, 'app.js');
    const indexPath = path.join(rootDir, 'index.js');
    const serverPath = path.join(rootDir, 'server.js');
    if (await isDirectory(routesPath)) return rootDir;
    if (await pathExists(appJsPath)) return rootDir;
    if (await pathExists(indexPath)) return rootDir;
    if (await pathExists(serverPath)) return rootDir;
    return null;
}

async function detectFrontendFallback(rootDir, pkgInfo, backendDir) {
    const deps = pkgInfo.dependencies || {};
    const hasAppVue = await pathExists(path.join(rootDir, 'App.vue'));
    const hasPagesDir = await isDirectory(path.join(rootDir, 'pages'));
    const hasNuxtConfig =
        (await pathExists(path.join(rootDir, 'nuxt.config.js'))) ||
        (await pathExists(path.join(rootDir, 'nuxt.config.ts')));
    const hasViteConfig =
        (await pathExists(path.join(rootDir, 'vite.config.js'))) ||
        (await pathExists(path.join(rootDir, 'vite.config.ts')));
    const hasSrc = await isDirectory(path.join(rootDir, 'src'));
    const looksLikeNuxt = hasNuxtConfig || deps.nuxt || (hasAppVue && hasPagesDir);
    const looksLikeVite = (deps.vite || hasViteConfig) && hasSrc;
    const looksLikeReact = deps.react && hasSrc;
    if ((looksLikeNuxt || looksLikeVite || looksLikeReact) && (!backendDir || path.resolve(backendDir) !== path.resolve(rootDir))) {
        return rootDir;
    }
    return null;
}

/**
 * @param {string} sourceRoot - 프로젝트 루트
 * @param {{ backendHint?: string, frontendHint?: string }} options
 */
export async function scanProject(sourceRoot, options = {}) {
    if (!(await isDirectory(sourceRoot))) {
        throw new Error(`소스 경로가 디렉터리가 아닙니다: ${sourceRoot}`);
    }

    const { backendHint, frontendHint } = options;
    const pkgInfo = await readPackageJson(sourceRoot);

    let backendDir = backendHint
        ? path.resolve(sourceRoot, backendHint)
        : await detectByCandidate(sourceRoot, BACKEND_CANDIDATES);
    if (!backendDir || !(await isDirectory(backendDir))) {
        backendDir = await detectBackendFallback(sourceRoot);
    }
    if (backendDir) {
        const backendPkg = await readPackageJson(backendDir);
        if (!hasExpress(backendPkg.dependencies)) {
            backendDir = null;
        }
    }

    let frontendDir = frontendHint
        ? path.resolve(sourceRoot, frontendHint)
        : await detectByCandidate(sourceRoot, FRONTEND_CANDIDATES);
    if (!frontendDir || !(await isDirectory(frontendDir))) {
        frontendDir = await detectFrontendFallback(sourceRoot, pkgInfo, backendDir);
    }
    if (frontendDir) {
        const frontPkg = await readPackageJson(frontendDir);
        if (!hasVue(frontPkg.dependencies) && !hasReact(frontPkg.dependencies)) {
            frontendDir = null;
        }
    }

    const backendEntry = backendDir ? await detectBackendEntry(backendDir) : null;
    const frontendPackageJson = frontendDir ? (await readPackageJson(frontendDir)).packageJson : null;
    const frontendBuildCommand = frontendPackageJson ? await detectFrontendBuildCommand(frontendPackageJson) : null;
    const frontendDistDir = frontendDir && frontendPackageJson ? await detectFrontendDistDir(frontendDir, frontendPackageJson) : 'dist';

    return {
        sourceRoot,
        backendDir,
        frontendDir,
        backendEntry,
        frontendBuildCommand,
        frontendDistDir,
        packageJson: pkgInfo.packageJson,
    };
}
