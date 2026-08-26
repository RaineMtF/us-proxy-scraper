import { inspectProxy } from './proxyInspector';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const CONCURRENCY = 20000;
const TIMEOUT_MS = 30000;
const RAW_JSON_PATH = join('.', 'data', 'raw.json');
const OUTPUT_JSON_PATH = join('.', 'data', 'checked.json');
const OUTPUT_TXT_PATH = join('.', 'data', 'checked.txt');

// 读取原始代理数据
function loadProxies() {
    try {
        const data = readFileSync(RAW_JSON_PATH, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        console.error('读取 raw.json 失败:', error.message);
        process.exit(1);
    }
}

// 将代理数据转换为代理 URL
function buildProxyUrl(proxy) {
    const type = proxy.type;
    const ip = proxy.ip;
    const port = proxy.port;
    return `${type}://${ip}:${port}`;
}

// 检测单个代理
async function checkSingleProxy(proxyData) {
    const proxyUrl = buildProxyUrl(proxyData);
    const report = await inspectProxy(proxyUrl, TIMEOUT_MS);
    return { proxyData, report };
}

// 并发控制检测 - 前60s均摊启动，之后填充空位
async function checkProxiesWithConcurrency(proxies, concurrency) {
    const results = [];
    const queue = [...proxies];
    const total = proxies.length;
    let processed = 0;

    async function worker() {
        while (queue.length > 0) {
            const proxy = queue.shift();
            if (!proxy) break;
            try {
                const result = await checkSingleProxy(proxy);
                results.push(result);
            } catch (error) {
                console.error(`检测失败 ${buildProxyUrl(proxy)}:`, error.message);
            } finally {
                processed++;
                if (processed % 100 === 0 || processed === total) {
                    console.log(`完成进度: ${processed}/${total}`);
                }
            }
        }
    }

    // 启动所有 worker，但它们会自己控制启动节奏
    const workers = Array(concurrency).fill().map(() => worker());
    await Promise.all(workers);

    return results;
}

// 主函数
async function main() {
    console.log('开始读取代理数据...');
    const proxies = loadProxies();
    console.log(`共读取 ${proxies.length} 个代理`);
    console.log(`并发数: ${CONCURRENCY}, 超时: ${TIMEOUT_MS}ms\n`);

    console.log('开始检测代理...');
    const startTime = Date.now();
    const results = await checkProxiesWithConcurrency(proxies, CONCURRENCY);
    const duration = (Date.now() - startTime) / 1000;

    // 筛选通过检测的代理
    const passedProxies = results.filter(({ report }) => {
        return report.passAll === true && report.error === null;
    });

    console.log(`\n检测完成，耗时 ${duration.toFixed(2)} 秒`);
    console.log(`通过检测: ${passedProxies.length}/${results.length}`);

    // 构建所有结果的 JSON 输出（包含通过和未通过的）
    const allResultsOutput = results.map(({ proxyData, report }) => ({
        // 原始字段
        ...proxyData,
        // check 字段（包含 alive, latency, tlsSecure）
        check_report: {
            alive: report.alive,
            latency_cf: report.latencyCf,
            latency_openssh: report.latencyOpenssh,
            tlsSecure: report.tlsSecure,
            error: report.error
        }
    }));

    // 写入 JSON 输出文件（所有节点）
    try {
        writeFileSync(OUTPUT_JSON_PATH, JSON.stringify(allResultsOutput, null, 4), 'utf-8');
        console.log(`\nJSON 结果已保存到: ${OUTPUT_JSON_PATH}`);
        console.log(`总代理数: ${allResultsOutput.length}`);
    } catch (error) {
        console.error('写入 JSON 结果失败:', error.message);
        process.exit(1);
    }

    // 构建通过的代理的 TXT 输出
    // 格式: type://ip:port#encodeURIComponent[country_code TYPE (city, country) ip:port]
    try {
        const txtContent = passedProxies.map(({ proxyData }) => {
            const type = proxyData.type;
            const ip = proxyData.ip;
            const port = proxyData.port;

            // 获取代理数据中的位置信息
            const countryCode = proxyData.country_code || '';
            const country = proxyData.country || '';
            const city = proxyData.city || '';

            // 构建 URL 编码的部分，格式与 ProxyNode.__repr__ 保持一致
            // {country_code} {type.upper()} ({city}, {country}) {ip}:{port}
            const name = encodeURIComponent(
                `${countryCode} ${type.toUpperCase()} (${city}, ${country}) ${ip}:${port}`
            );

            return `${type}://${ip}:${port}#${name}`;
        }).join('\n');

        writeFileSync(OUTPUT_TXT_PATH, txtContent, 'utf-8');
        console.log(`TXT 结果已保存到: ${OUTPUT_TXT_PATH}`);
        console.log(`TXT 有效代理数: ${passedProxies.length}`);
    } catch (error) {
        console.error('写入 TXT 结果失败:', error.message);
        process.exit(1);
    }
}

main().catch(error => {
    console.error('程序错误:', error);
    process.exit(1);
});
