/**
 * dok lang — CLI 언어 설정 변경
 *
 * 사용법:
 *   dok lang              인터랙티브 선택 (12개 언어 리스트)
 *   dok lang en           영어로 즉시 변경
 *   dok lang ko           한국어로 즉시 변경
 *   dok lang --list       지원 언어 목록만 출력
 *   dok lang --show       현재 설정된 언어 출력
 *
 * 설정 저장 위치: ~/.dokkebi/config.json
 * 환경변수 우선: DOKKEBI_LANG 가 설정된 경우 config 값보다 우선합니다.
 */

import os from 'os';
import path from 'path';
import inquirer from 'inquirer';
import { t, getLang, setLang, listLangs } from '../i18n/index.js';

const CONFIG_PATH = path.join(os.homedir(), '.dokkebi', 'config.json');

export async function runLang(code, options = {}) {
    const langs = listLangs();

    if (options.list) {
        console.log(t('lang.title'));
        console.log('');
        for (const l of langs) {
            console.log(`  ${l.code.padEnd(4)}  ${l.native.padEnd(14)}  (${l.name})`);
        }
        return;
    }

    if (options.show) {
        const cur = getLang();
        const found = langs.find((l) => l.code === cur);
        const native = found ? found.native : cur;
        console.log(t('lang.current', { native, code: cur }));
        const env = process.env.DOKKEBI_LANG;
        if (env && env.trim()) {
            console.log(t('lang.envOverride', { env }));
        }
        return;
    }

    let target = (code || '').trim().toLowerCase();

    // 직접 코드 지정이 없으면 인터랙티브 선택
    if (!target) {
        const cur = getLang();
        const curEntry = langs.find((l) => l.code === cur);
        console.log('');
        console.log(t('lang.title'));
        console.log(t('lang.current', {
            native: curEntry ? curEntry.native : cur,
            code:   cur,
        }));
        console.log('');

        const { selected } = await inquirer.prompt([
            {
                type: 'list',
                name: 'selected',
                message: t('lang.select'),
                default: cur,
                choices: langs.map((l) => ({
                    name:  `${l.native.padEnd(12)}  (${l.name} — ${l.code})`,
                    value: l.code,
                })),
            },
        ]);
        target = selected;
    }

    const found = langs.find((l) => l.code === target);
    if (!found) {
        const available = langs.map((l) => l.code).join(', ');
        console.error(t('lang.invalid', { code: target }));
        console.error(t('lang.available', { list: available }));
        process.exitCode = 1;
        return;
    }

    const ok = setLang(target);
    if (!ok) {
        console.error(t('lang.writeFailed'));
        process.exitCode = 1;
        return;
    }

    // 새 언어로 즉시 메시지 출력 (setLang 내부에서 _currentLang 업데이트됨)
    console.log('');
    console.log(t('lang.changed', { native: found.native, code: target }));
    console.log(t('lang.savedAt', { path: CONFIG_PATH }));

    const env = process.env.DOKKEBI_LANG;
    if (env && env.trim() && env.trim().toLowerCase() !== target) {
        console.log(t('lang.envOverride', { env }));
    }
}
