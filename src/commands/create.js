#!/usr/bin/env node
import path from 'path';
import fs from 'fs/promises';
import { execFileSync } from 'child_process';
import inquirer from 'inquirer';
import { generateProject } from '../core/projectGenerator.js';
import { t } from '../i18n/index.js';

const BANNER = `
  ██████╗  ██████╗ ██╗  ██╗██╗  ██╗███████╗██████╗ ██╗
  ██╔══██╗██╔═══██╗██║ ██╔╝██║ ██╔╝██╔════╝██╔══██╗██║
  ██║  ██║██║   ██║█████╔╝ █████╔╝ █████╗  ██████╔╝██║
  ██║  ██║██║   ██║██╔═██╗ ██╔═██╗ ██╔══╝  ██╔══██╗██║
  ██████╔╝╚██████╔╝██║  ██╗██║  ██╗███████╗██████╔╝██║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝
`;

/**
 * 인터랙티브 프로젝트 생성 커맨드 (Nuxt 스타일)
 * @param {object} options - { name?, frontend?, database? }
 */
export async function runCreate(options = {}) {
    console.log(BANNER);
    console.log('  ' + t('create.banner'));
    console.log('');
    console.log('  ' + t('cli.langHint'));
    console.log('');

    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'name',
            message: t('create.promptName'),
            default: options.name || 'my-dokkebi-app',
            validate: (v) =>
                /^[a-z0-9][a-z0-9-_]*$/.test(v) ||
                t('create.validateName'),
            when: !options.name,
        },
        {
            type: 'list',
            name: 'frontend',
            message: t('create.promptFrontend'),
            choices: [
                { name: t('create.choices.react'), value: 'react' },
                { name: t('create.choices.vue'),   value: 'vue' },
            ],
            when: !options.frontend,
        },
        {
            type: 'list',
            name: 'database',
            message: t('create.promptDatabase'),
            choices: [
                { name: t('create.choices.d1'),       value: 'd1' },
                { name: t('create.choices.supabase'), value: 'supabase' },
                { name: t('create.choices.appwrite'), value: 'appwrite' },
            ],
            when: !options.database,
        },
        {
            type: 'confirm',
            name: 'withAuth',
            message: t('create.promptAuth'),
            default: true,
        },
        {
            type: 'list',
            name: 'proxyMode',
            message: t('create.promptProxyMode'),
            choices: [
                { name: t('create.choices.server'),     value: 'server' },
                { name: t('create.choices.serverless'), value: 'serverless' },
            ],
        },
        {
            type: 'confirm',
            name: 'withWebAuthn',
            message: t('create.promptWebAuthn'),
            default: false,
            when: (cur) => cur.withAuth !== false,
        },
        {
            type: 'confirm',
            name: 'installDeps',
            message: t('create.promptInstall'),
            default: true,
        },
    ]);

    const projectName = options.name || answers.name;
    const frontend = options.frontend || answers.frontend;
    const database = options.database || answers.database;
    const { withAuth, withWebAuthn = false, proxyMode = 'server', installDeps } = answers;

    const targetDir = path.resolve(process.cwd(), projectName);

    let dirExists = false;
    try {
        await fs.access(targetDir);
        dirExists = true;
    } catch {
        /* 정상: 폴더 없음 */
    }

    if (dirExists) {
        const { overwrite } = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'overwrite',
                message: t('create.promptOverwrite', { name: projectName }),
                default: false,
            },
        ]);
        if (!overwrite) {
            console.log('\n' + t('create.cancelled') + '\n');
            return;
        }
        await fs.rm(targetDir, { recursive: true, force: true });
    }

    console.log(
        `\n${t('create.creating', { name: projectName })} (${frontend} + ${database}${withAuth ? ' + auth' : ''})...\n`
    );

    await generateProject({
        name: projectName,
        targetDir,
        frontend,
        database,
        withAuth,
        proxyMode,
        withWebAuthn,
    });

    if (installDeps) {
        const path = (await import('path')).default;
        const frontendDir = path.join(targetDir, 'frontend');

        console.log('\n' + t('create.installRoot'));
        try {
            execFileSync('npm', ['install'], { cwd: targetDir, stdio: 'inherit' });
        } catch (e) {
            console.warn(t('create.installRootFailed'), e.message);
        }

        console.log(t('create.installFrontend'));
        try {
            execFileSync('npm', ['install'], { cwd: frontendDir, stdio: 'inherit' });
        } catch (e) {
            console.warn(t('create.installFrontendFailed'), e.message);
        }
    }

    const proxyModeLabel = proxyMode === 'serverless'
        ? t('create.proxyModeServerless')
        : t('create.proxyModeServer');

    const serverlessExtra = proxyMode === 'serverless' ? `
  ${t('create.serverlessDeploy')}
    ${t('create.serverlessDeployCmd')}

  ${t('create.serverlessLocal')}
    ${t('create.serverlessLocalCmd')}
` : `
  ${t('create.devServer')}
    ${t('create.devServerCmd')}
`;

    const startCmd = installDeps
        ? t('create.afterInstall')
        : t('create.beforeInstall');

    const frontendLabel = frontend === 'react'
        ? t('create.frontendReact')
        : t('create.frontendVue');

    const workerLines = proxyMode === 'serverless'
        ? `    worker/          ← ${t('create.workerComment')}\n    wrangler.toml    ← ${t('create.wranglerComment')}\n`
        : '';

    const webauthnBlock = withWebAuthn ? `

  ${t('create.webauthnNotice')}
  ────────────────────────────────────────
   ${t('create.webauthnGuide')}
  ────────────────────────────────────────` : '';

    console.log(`
╔════════════════════════════════════════╗
║  ${t('create.completeTitle')}           ║
╚════════════════════════════════════════╝

  ${t('create.nextSteps')}

    cd ${projectName}
${startCmd}

  ${t('create.realDb')}
    ${t('create.realDbCmd')}
${serverlessExtra}
  ${t('create.proxyModeLabel')} ${proxyModeLabel}${webauthnBlock}

  ${t('create.structure')}
    backend/
      controllers/   ← ${t('create.controllersComment')}
      models/        ← ${t('create.modelsComment')}
      middleware/    ← ${t('create.middlewareComment')}
      wit/           ← ${t('create.witComment')}
    frontend/        ← ${frontendLabel}
${workerLines}    dokkebi.config.js
    .env.example     ← ${t('create.envComment')}

  ${t('create.dbLabel')} ${dbLabel(database)}
  ${t('create.securityLabel')}
`);
}

function dbLabel(db) {
    return {
        d1:       t('create.dbD1'),
        supabase: t('create.dbSupabase'),
        appwrite: t('create.dbAppwrite'),
    }[db];
}
