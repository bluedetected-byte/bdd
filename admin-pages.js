'use strict';

const PAGE_SIZE = 25;
const KEY_STATUSES = Object.freeze(['all', 'available', 'used', 'expired', 'revoked']);

function parsePage(value) {
  if (value === undefined) return 1;
  if (typeof value !== 'string' || !/^\d{1,7}$/.test(value)) return 1;
  const page = Number(value);
  return Number.isSafeInteger(page) && page > 0 ? page : 1;
}

function pageCount(total, pageSize = PAGE_SIZE) {
  return Math.max(1, Math.ceil(Math.max(0, total) / pageSize));
}

function pageWindow(requestedPage, total, pageSize = PAGE_SIZE) {
  const pages = pageCount(total, pageSize);
  const page = Math.min(Math.max(1, requestedPage), pages);
  return { page, pages, limit: pageSize, offset: (page - 1) * pageSize };
}

function parseSearch(value) {
  if (typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ').slice(0, 100);
}

function parseKeyStatus(value) {
  return typeof value === 'string' && KEY_STATUSES.includes(value) ? value : 'all';
}

function paginationLinks(basePath, pageParam, page, pages, preservedParams = {}) {
  if (pages <= 1) return '';
  const query = (targetPage) => {
    const params = new URLSearchParams([[pageParam, String(targetPage)]]);
    for (const [key, value] of Object.entries(preservedParams)) {
      if (typeof value === 'string' && value !== '') params.set(key, value);
    }
    return `${basePath}?${params.toString()}`;
  };
  const previous = page > 1
    ? `<a href="${query(page - 1)}" rel="prev">Previous</a>`
    : '<span class="disabled">Previous</span>';
  const next = page < pages
    ? `<a href="${query(page + 1)}" rel="next">Next</a>`
    : '<span class="disabled">Next</span>';
  return `<nav class="pagination" aria-label="Pagination">${previous}<span>Page ${page} of ${pages}</span>${next}</nav>`;
}

module.exports = {
  KEY_STATUSES,
  PAGE_SIZE,
  pageCount,
  pageWindow,
  paginationLinks,
  parseKeyStatus,
  parsePage,
  parseSearch
};
