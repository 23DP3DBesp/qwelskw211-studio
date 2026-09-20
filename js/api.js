'use strict';
// Shared by classic deferred scripts and imported by the regression tests.
globalThis.portfolioAPI = async function (path, options = {}) {
  const ru = typeof document === 'undefined' || document.documentElement.lang === 'ru';
  const message = (en, ruText) => ru ? ruText : en;
  let response;
  try {
    response = await fetch(path, {
      ...options,
      credentials: 'same-origin',
      redirect: 'error',
      headers: {Accept: 'application/json', ...(typeof options.body === 'string' ? {'Content-Type': 'application/json'} : {}), ...options.headers},
    });
  } catch {
    throw new Error(message('Connection failed. Check your connection and reload the page to sign in again.', 'Не удалось подключиться. Проверьте интернет и обновите страницу для повторного входа.'));
  }
  if (response.status === 401 && path !== '/api/auth/login') throw new Error(message('Your session expired. Reload the page to sign in again.', 'Сессия истекла. Обновите страницу и войдите снова.'));
  if (typeof location !== 'undefined' && ['localhost','127.0.0.1'].includes(location.hostname) && location.port === '5500') throw new Error('Открыт статический сервер без базы данных. Запустите npm run dev и откройте http://127.0.0.1:4173.');
  if (!/^application\/(?:[\w.-]+\+)?json\b/i.test(response.headers.get('Content-Type') || '')) {
    throw new Error(message('The server returned a page instead of data. Reload the page and sign in again. If this persists, the service is unavailable.', 'Сервер вернул страницу вместо данных. Обновите страницу и войдите снова. Если ошибка повторяется, сервис недоступен.'));
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error(message('The server returned invalid data. Please try again later.', 'Сервер вернул некорректные данные. Повторите попытку позже.')); }
  if (!response.ok) throw Object.assign(new Error(typeof data?.error === 'string' ? data.error : message(`Request failed (${response.status}).`, `Не удалось выполнить запрос (${response.status}).`)), {field:data?.field});
  if (!data || typeof data !== 'object') throw new Error(message('The server returned incomplete data.', 'Сервер вернул неполные данные.'));
  return data;
};
