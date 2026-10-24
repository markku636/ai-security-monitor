// 網站掃描測試用的掃描器原始輸出（httpx／tlsx／nuclei／testssl 的真實欄位格式）。
export const HTTPX_OUT = JSON.stringify({ url: 'https://shop.example.com', status_code: 200, title: 'Shop', webserver: 'nginx', tech: ['Nginx', 'PHP'], host: '93.184.216.34', failed: false });
export const TLSX_OUT = JSON.stringify({
  host: 'shop.example.com',
  ip: '93.184.216.34',
  port: '443',
  probe_status: true,
  tls_version: 'tls10',
  cipher: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  // 相對於現在：3.5 天後到期（寫死日期的話，過了那天測試就會壞）
  not_after: new Date(Date.now() + 3.5 * 86_400_000).toISOString(),
  subject_cn: 'shop.example.com',
  subject_an: ['shop.example.com'],
  issuer_cn: 'shop.example.com',
  self_signed: true,
});
export const NUCLEI_OUT = [
  JSON.stringify({
    'template-id': 'http-missing-security-headers',
    info: { name: 'HTTP Missing Security Headers', severity: 'info', tags: ['misconfig', 'headers'], classification: { 'cve-id': null, 'cwe-id': ['cwe-693'] } },
    type: 'http',
    'matched-at': 'https://shop.example.com/',
    'matcher-name': 'strict-transport-security',
  }),
  JSON.stringify({
    'template-id': 'CVE-2021-41773',
    info: {
      name: 'Apache 2.4.49 - Path Traversal',
      severity: 'high',
      description: 'Path traversal in Apache HTTP Server 2.4.49',
      reference: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
      classification: { 'cve-id': ['cve-2021-41773'], 'cwe-id': ['CWE-22'], 'cvss-score': 7.5, 'epss-score': 0.97 },
    },
    type: 'http',
    'matched-at': 'https://shop.example.com/cgi-bin/.%2e/.%2e/etc/passwd',
    'extracted-results': ['root:x:0:0:root:/root:/bin/bash', 'AKIAABCDEFGHIJKLMNOPQRSTUV1234'],
  }),
  '{"template-id": "truncated',
  '',
].join('\n');
export const TESTSSL_OUT = JSON.stringify([
  { id: 'engine_problem', severity: 'WARN', finding: 'No engine or GOST support' },
  { id: 'SSLv2', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'OK', finding: 'not offered' },
  { id: 'TLS1', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'LOW', finding: 'offered (deprecated)' },
  { id: 'BREACH', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'MEDIUM', cve: 'CVE-2013-3587', cwe: 'CWE-310', finding: 'potentially VULNERABLE' },
  { id: 'some_new_check', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'HIGH', finding: 'bad' },
]);
// testssl 真實輸出的樣子：每個加密套件一筆、加密套件順序、總評等級（應該合併／略過）
export const WEAK_CIPHERS_OUT = JSON.stringify([
  { id: 'cipher_order-tls1_2', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'LOW', finding: 'server -- TLS 1.2 ciphers not prioritized' },
  { id: 'cipher_order', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'LOW', finding: 'Server does not prioritize ciphers' },
  { id: 'cipher-tls1_2_xc013', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'LOW', finding: 'TLSv1.2   xc013   ECDHE-RSA-AES128-SHA' },
  { id: 'cipher-tls1_2_x2f', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'LOW', finding: 'TLSv1.2   x2f     AES128-SHA' },
  { id: 'cipher-tls1_x0a', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'MEDIUM', finding: 'TLSv1     x0a     DES-CBC3-SHA' },
  { id: 'overall_grade', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'CRITICAL', finding: 'T' },
  { id: 'grade_cap_reason_1', ip: 'shop.example.com/93.184.216.34', port: '443', severity: 'INFO', finding: 'Grade capped to T. Issues with the chain of trust' },
]);
