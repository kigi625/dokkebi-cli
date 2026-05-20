/**
 * dokkebi-cli i18n (다국어 지원)
 *
 * 사용법:
 *   import { t, getLang, setLang, listLangs } from '../i18n/index.js';
 *
 *   t('build.step1')                 // 번역된 문자열
 *   t('build.complete', { mode })    // 템플릿 변수 치환 ({mode} → 값)
 *   getLang()                        // 'ko'
 *   setLang('en')                    // ~/.dokkebi/config.json 에 저장
 *   listLangs()                      // [{ code, name, native }, ...]
 *
 * 언어 결정 우선순위:
 *   1. process.env.DOKKEBI_LANG
 *   2. ~/.dokkebi/config.json 의 lang
 *   3. 기본값 'ko'
 *
 * 키 누락 시 폴백:
 *   현재 언어 → 'ko' → 키 자체
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LOCALES_DIR = path.join(__dirname, 'locales');
const CONFIG_DIR = path.join(os.homedir(), '.dokkebi');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const DEFAULT_LANG = 'ko';
const FALLBACK_LANG = 'en';

const SUPPORTED_LANGS = [
    { code: 'ko', name: 'Korean',     native: '한국어' },
    { code: 'en', name: 'English',    native: 'English' },
    { code: 'ja', name: 'Japanese',   native: '日本語' },
    { code: 'zh', name: 'Chinese',    native: '中文' },
    { code: 'de', name: 'German',     native: 'Deutsch' },
    { code: 'es', name: 'Spanish',    native: 'Español' },
    { code: 'fr', name: 'French',     native: 'Français' },
    { code: 'it', name: 'Italian',    native: 'Italiano' },
    { code: 'ru', name: 'Russian',    native: 'Русский' },
    { code: 'vi', name: 'Vietnamese', native: 'Tiếng Việt' },
    { code: 'th', name: 'Thai',       native: 'ไทย' },
    { code: 'pt', name: 'Portuguese', native: 'Português' },
];

const require_ = createRequire(import.meta.url);

const _cache = {};
let _currentLang = null;

function _readConfig() {
    try {
        const raw = fs.readFileSync(CONFIG_FILE, 'utf-8');
        return JSON.parse(raw);
    } catch {
        return {};
    }
}

function _writeConfig(cfg) {
    try {
        fs.mkdirSync(CONFIG_DIR, { recursive: true });
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf-8');
        return true;
    } catch {
        return false;
    }
}

function _loadLocale(lang) {
    if (_cache[lang]) return _cache[lang];
    try {
        const file = path.join(LOCALES_DIR, `${lang}.json`);
        const raw = fs.readFileSync(file, 'utf-8');
        _cache[lang] = JSON.parse(raw);
        return _cache[lang];
    } catch {
        _cache[lang] = null;
        return null;
    }
}

function _lookup(obj, key) {
    if (!obj) return undefined;
    const parts = key.split('.');
    let cur = obj;
    for (const p of parts) {
        if (cur && typeof cur === 'object' && p in cur) cur = cur[p];
        else return undefined;
    }
    return typeof cur === 'string' ? cur : undefined;
}

function _interpolate(str, params) {
    if (!params || typeof str !== 'string') return str;
    return str.replace(/\{(\w+)\}/g, (m, k) => (k in params ? String(params[k]) : m));
}

/**
 * 현재 설정된 언어 코드를 반환합니다.
 * 우선순위: env DOKKEBI_LANG → config.json → 기본값 ko
 */
export function getLang() {
    if (_currentLang) return _currentLang;
    const envLang = (process.env.DOKKEBI_LANG || '').trim().toLowerCase();
    if (envLang && SUPPORTED_LANGS.some((l) => l.code === envLang)) {
        _currentLang = envLang;
        return envLang;
    }
    const cfg = _readConfig();
    const lang = (cfg.lang || '').trim().toLowerCase();
    if (lang && SUPPORTED_LANGS.some((l) => l.code === lang)) {
        _currentLang = lang;
        return lang;
    }
    _currentLang = DEFAULT_LANG;
    return DEFAULT_LANG;
}

/**
 * 언어를 설정하고 ~/.dokkebi/config.json 에 저장합니다.
 * @param {string} lang - 언어 코드 (예: 'ko', 'en', 'ja')
 * @returns {boolean} 성공 여부
 */
export function setLang(lang) {
    const code = String(lang || '').trim().toLowerCase();
    if (!SUPPORTED_LANGS.some((l) => l.code === code)) return false;
    const cfg = _readConfig();
    cfg.lang = code;
    const ok = _writeConfig(cfg);
    if (ok) _currentLang = code;
    return ok;
}

/**
 * 지원 언어 목록을 반환합니다.
 * @returns {Array<{code: string, name: string, native: string}>}
 */
export function listLangs() {
    return SUPPORTED_LANGS.slice();
}

/**
 * 번역 문자열을 반환합니다.
 * @param {string} key - 점(.) 표기 키 (예: 'build.step1')
 * @param {Object} [params] - 템플릿 변수 ({foo} → params.foo)
 * @returns {string}
 */
export function t(key, params) {
    const lang = getLang();
    const data = _loadLocale(lang);
    let str = _lookup(data, key);
    if (str === undefined && lang !== FALLBACK_LANG) {
        const fbEn = _loadLocale(FALLBACK_LANG);
        str = _lookup(fbEn, key);
    }
    if (str === undefined && lang !== DEFAULT_LANG && FALLBACK_LANG !== DEFAULT_LANG) {
        const fbKo = _loadLocale(DEFAULT_LANG);
        str = _lookup(fbKo, key);
    }
    if (str === undefined) str = key;
    return _interpolate(str, params);
}

/**
 * 번역 키가 존재하는지 확인합니다.
 */
export function hasKey(key) {
    const lang = getLang();
    const data = _loadLocale(lang) || _loadLocale(DEFAULT_LANG);
    return _lookup(data, key) !== undefined;
}

/**
 * 캐시를 초기화합니다 (주로 테스트용).
 */
export function _resetCache() {
    for (const k of Object.keys(_cache)) delete _cache[k];
    _currentLang = null;
}
