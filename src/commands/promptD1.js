import inquirer from 'inquirer';
import { t } from '../i18n/index.js';

/**
 * Cloudflare D1 연결 정보를 CLI로 입력받음
 */
export async function promptD1Config() {
    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'accountId',
            message: t('promptD1.accountId'),
            default: process.env.CLOUDFLARE_ACCOUNT_ID || '',
        },
        {
            type: 'input',
            name: 'databaseId',
            message: t('promptD1.databaseId'),
            default: process.env.CLOUDFLARE_D1_DATABASE_ID || '',
        },
        {
            type: 'password',
            name: 'apiToken',
            message: t('promptD1.apiToken'),
            default: process.env.CLOUDFLARE_API_TOKEN || '',
        },
        {
            type: 'input',
            name: 'apiBase',
            message: 'API Base URL:',
            default: process.env.CLOUDFLARE_API_BASE || 'https://api.cloudflare.com/client/v4',
        },
    ]);
    return {
        accountId: String(answers.accountId || '').trim(),
        databaseId: String(answers.databaseId || '').trim(),
        apiToken: String(answers.apiToken || '').trim(),
        apiBase: String(answers.apiBase || 'https://api.cloudflare.com/client/v4').trim(),
    };
}

/**
 * D1 마이그레이션/데이터 복사 옵션
 */
export async function promptD1Options() {
    const { runMigrations } = await inquirer.prompt([
        {
            type: 'confirm',
            name: 'runMigrations',
            message: t('promptD1.applyMigrations'),
            default: true,
        },
    ]);
    let migrateFromMysql = false;
    let mysqlSourceConfig = null;
    const { copyFromMysql } = await inquirer.prompt([
        {
            type: 'confirm',
            name: 'copyFromMysql',
            message: t('promptD1.copyFromMysql'),
            default: false,
        },
    ]);
    if (copyFromMysql) {
        migrateFromMysql = true;
        mysqlSourceConfig = await inquirer.prompt([
            { type: 'input',    name: 'host',     message: t('promptD1.mysqlHost'),     default: '127.0.0.1' },
            { type: 'input',    name: 'port',     message: t('promptD1.mysqlPort'),     default: '3306' },
            { type: 'input',    name: 'user',     message: t('promptD1.mysqlUser'),     default: 'root' },
            { type: 'password', name: 'password', message: t('promptD1.mysqlPassword'), default: '' },
            { type: 'input',    name: 'database', message: t('promptD1.mysqlDatabase'), default: '' },
        ]);
        mysqlSourceConfig.port = Number(mysqlSourceConfig.port) || 3306;
    }
    return { runMigrations, migrateFromMysql, mysqlSourceConfig };
}
