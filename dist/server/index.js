//#region admin/login.html?raw
var login_default = "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>Вход — QWELSKW</title><link rel=\"stylesheet\" href=\"/css/admin.css?v=6\"><script src=\"/js/api.js\" defer><\/script><script src=\"/js/login.js\" defer><\/script></head><body><header class=\"admin-header\"><a href=\"/\">QWELSKW <small>PORTFOLIO</small></a></header><main class=\"admin-main login-main\"><p class=\"label\">ДЛЯ ВЛАДЕЛЬЦА</p><h1>Вход в управление</h1><form id=\"login-form\"><label>Логин<input name=\"username\" autocomplete=\"username\" maxlength=\"100\" required autofocus></label><label>Пароль<input name=\"password\" type=\"password\" autocomplete=\"current-password\" maxlength=\"256\" required></label><button class=\"primary\" type=\"submit\">Войти</button><p id=\"login-status\" role=\"status\" aria-live=\"polite\"></p></form><p><a href=\"/\">Вернуться в портфолио</a></p></main></body></html>\n";
//#endregion
//#region server/password-auth.js
var enc = new TextEncoder();
var hex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
var digest = async (value) => hex(await crypto.subtle.digest("SHA-256", enc.encode(value)));
var query = (env, sql, ...args) => env.DB.prepare(sql).bind(...args);
var cookieName = (request) => new URL(request.url).protocol === "https:" ? "__Host-portfolio_session" : "portfolio_local_session";
var sessionToken = (request) => {
	const value = (request.headers.get("Cookie") || "").split(";").map((v) => v.trim()).find((v) => v.startsWith(cookieName(request) + "="))?.split("=")[1];
	return /^[a-f0-9]{64}$/.test(value || "") ? value : null;
};
var cookie = (request, token, age) => `${cookieName(request)}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${new URL(request.url).protocol === "https:" ? "; Secure" : ""}`;
var passwordMode = (env) => !!env.ADMIN_PASSWORD_HASH;
async function passwordIdentity(request, env) {
	const token = sessionToken(request);
	if (!token) return null;
	const row = await query(env, "SELECT credential_version FROM admin_sessions WHERE token_hash=? AND expires>?", await digest(token), Date.now()).first();
	if (!row || row.credential_version !== await digest(env.ADMIN_PASSWORD_HASH)) return null;
	return {
		id: "password-owner",
		email: env.ADMIN_USERNAME || "admin"
	};
}
async function authRoute(request, env, { json, fail, body, sameOrigin }) {
	const url = new URL(request.url), path = url.pathname;
	if (path === "/admin/login") {
		if (!passwordMode(env)) return Response.redirect(`${url.origin}/signin-with-chatgpt?return_to=%2Fadmin`, 302);
		if (await passwordIdentity(request, env)) return Response.redirect(`${url.origin}/admin`, 302);
		return new Response(login_default, { headers: {
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "no-store",
			"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'"
		} });
	}
	if (path !== "/api/auth/login" && path !== "/api/auth/logout") return null;
	if (request.method !== "POST") fail("Method not allowed", 405);
	sameOrigin(request);
	if (path === "/api/auth/logout") {
		const token = sessionToken(request);
		if (token) await query(env, "DELETE FROM admin_sessions WHERE token_hash=?", await digest(token)).run();
		return new Response(null, {
			status: 303,
			headers: {
				Location: "/admin/login",
				"Set-Cookie": cookie(request, "", 0),
				"Cache-Control": "no-store"
			}
		});
	}
	if (!passwordMode(env)) fail("Вход по паролю не настроен", 503);
	const value = await body(request, 4096);
	if (typeof value.username !== "string" || typeof value.password !== "string" || value.username.length > 100 || value.password.length > 256) fail("Неверный логин или пароль", 401);
	const current = Date.now();
	if ((await query(env, "INSERT INTO rate_limits (key,count,expires) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires<=? THEN 1 ELSE count+1 END, expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING count", "login:" + await digest(request.headers.get("CF-Connecting-IP") || "unknown"), current + 9e5, current, current).first()).count > 10) fail("Слишком много попыток. Попробуйте через 15 минут.", 429);
	const [scheme, saltHex, expected] = env.ADMIN_PASSWORD_HASH.split(":");
	if (scheme !== "pbkdf2-sha256-100000" || !/^([a-f0-9]{2}){16}$/.test(saltHex) || !/^[a-f0-9]{64}$/.test(expected)) fail("Вход временно недоступен", 503);
	const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(value.password), "PBKDF2", false, ["deriveBits"]);
	const salt = Uint8Array.from(saltHex.match(/../g), (v) => parseInt(v, 16));
	const actual = hex(await crypto.subtle.deriveBits({
		name: "PBKDF2",
		salt,
		iterations: 1e5,
		hash: "SHA-256"
	}, keyMaterial, 256));
	let difference = 0;
	for (let i = 0; i < expected.length; i++) difference |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
	if (difference || value.username !== (env.ADMIN_USERNAME || "admin")) fail("Неверный логин или пароль", 401);
	const token = hex(crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(32))), oldToken = sessionToken(request);
	const operations = [query(env, "DELETE FROM admin_sessions WHERE expires<=?", current)];
	if (oldToken) operations.push(query(env, "DELETE FROM admin_sessions WHERE token_hash=?", await digest(oldToken)));
	operations.push(query(env, "INSERT INTO admin_sessions (token_hash,expires,credential_version) VALUES (?,?,?)", await digest(token), current + 288e5, await digest(env.ADMIN_PASSWORD_HASH)));
	await env.DB.batch(operations);
	const response = json({ ok: true });
	response.headers.set("Set-Cookie", cookie(request, token, 28800));
	return response;
}
//#endregion
//#region server/seed.json
var seed_default = [
	{
		"id": "e-catalog",
		"category": "web",
		"status": "published",
		"position": 0,
		"title": {
			"en": "E-CATALOG",
			"ru": "E-CATALOG"
		},
		"description": {
			"en": "AI powered product catalog",
			"ru": "Каталог товаров с ИИ"
		},
		"result": {
			"en": "AI powered product catalog",
			"ru": "Каталог товаров с ИИ"
		},
		"cover": "/assets/images/project-01.jpg",
		"gallery": [],
		"video": "",
		"link": "",
		"tech": "Vue / JavaScript / Database / AI",
		"concept": true
	},
	{
		"id": "music-player",
		"category": "web",
		"status": "published",
		"position": 1,
		"title": {
			"en": "MUSIC PLAYER",
			"ru": "MUSIC PLAYER"
		},
		"description": {
			"en": "Modern web music experience",
			"ru": "Современный веб-плеер"
		},
		"result": {
			"en": "Modern web music experience",
			"ru": "Современный веб-плеер"
		},
		"cover": "/assets/images/project-02.jpg",
		"gallery": [],
		"video": "",
		"link": "",
		"tech": "JavaScript / API / UI",
		"concept": true
	},
	{
		"id": "web-application",
		"category": "web",
		"status": "published",
		"position": 2,
		"title": {
			"en": "WEB APPLICATION",
			"ru": "WEB APPLICATION"
		},
		"description": {
			"en": "Full stack project",
			"ru": "Full stack приложение"
		},
		"result": {
			"en": "Full stack project",
			"ru": "Full stack приложение"
		},
		"cover": "/assets/images/project-03.jpg",
		"gallery": [],
		"video": "",
		"link": "",
		"tech": "C# / .NET / SQL",
		"concept": true
	},
	{
		"id": "experiments",
		"category": "design",
		"status": "published",
		"position": 3,
		"title": {
			"en": "EXPERIMENTS",
			"ru": "EXPERIMENTS"
		},
		"description": {
			"en": "UI and frontend experiments",
			"ru": "Эксперименты с интерфейсами"
		},
		"result": {
			"en": "UI and frontend experiments",
			"ru": "Эксперименты с интерфейсами"
		},
		"cover": "/assets/images/project-04.jpg",
		"gallery": [],
		"video": "",
		"link": "",
		"tech": "HTML / CSS / JavaScript",
		"concept": true
	}
];
//#endregion
//#region admin/index.html?raw
var admin_default = "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>QWELSKW — Управление</title><link rel=\"stylesheet\" href=\"/css/admin.css?v=8\"><script src=\"/js/api.js?v=8\" defer><\/script><script src=\"/js/admin.js?v=8\" defer><\/script></head><body><!--ADMIN_BOOTSTRAP-->\r\n<header class=\"admin-header\"><a href=\"/\">QWELSKW <small>PORTFOLIO</small></a><div><span id=\"account\"></span> <a href=\"/signout-with-chatgpt?return_to=/\">Выйти</a></div></header>\r\n<main class=\"admin-main\"><div class=\"admin-heading\"><div><p class=\"label\">ТОЛЬКО ДЛЯ ВЛАДЕЛЬЦА</p><h1>Управление сайтом</h1></div><a href=\"/\" target=\"_blank\" rel=\"noopener\">Открыть сайт ↗</a></div>\r\n<nav class=\"admin-tabs\" aria-label=\"Разделы\"><button data-tab=\"projects\" aria-pressed=\"true\">Проекты</button><button data-tab=\"settings\" aria-pressed=\"false\">Тексты, услуги и контакты</button><button data-tab=\"inquiries\" aria-pressed=\"false\">Заявки</button></nav>\r\n<p id=\"status\" role=\"status\" aria-live=\"polite\"></p><div id=\"load-recovery\" hidden><button type=\"button\" id=\"retry-load\">Повторить загрузку</button> <a href=\"/signin-with-chatgpt?return_to=%2Fadmin\" target=\"_top\">Войти снова</a></div>\r\n<section id=\"projects-panel\"><div class=\"section-line\"><h2>Работы</h2><button id=\"new-project\" class=\"primary\">Добавить проект</button></div><p class=\"hint\">Меньшее число в поле «Порядок» поднимает работу выше. Черновики и скрытые работы видны только вам.</p><div id=\"project-list\"></div></section>\r\n<section id=\"settings-panel\" hidden><h2>Контакты</h2><form id=\"settings-form\"><div id=\"contact-fields\" class=\"field-grid\"></div><h2>Тексты и услуги · EN / RU</h2><p class=\"hint\">Измените тексты первого экрана, услуг, разделов и кнопок. Исходный английский текст помогает найти нужное место. Пустое поле использует исходный текст.</p><label>Найти текст<input type=\"search\" id=\"copy-search\" placeholder=\"Например: VIDEO, съёмка, CONTACT\"></label><div id=\"copy-fields\"></div><div class=\"sticky-actions\"><button class=\"primary\" type=\"submit\">Сохранить тексты и контакты</button></div></form></section>\r\n<section id=\"inquiries-panel\" hidden><h2>Заявки</h2><p class=\"hint\">Новые обращения с формы на сайте. Они сохраняются здесь; автоматические письма не отправляются.</p><div id=\"inquiry-list\"></div></section>\r\n</main>\r\n<dialog id=\"editor\" aria-labelledby=\"editor-title\"><form id=\"project-form\"><div class=\"section-line\"><h2 id=\"editor-title\">Проект</h2><button type=\"button\" id=\"close-editor\" aria-label=\"Закрыть редактор\">×</button></div>\r\n<div class=\"field-grid\"><label>Адрес работы<input name=\"id\" required pattern=\"[a-z0-9][a-z0-9\\-]{0,79}\" title=\"Строчные латинские буквы, цифры и дефисы. Например: my-project\" maxlength=\"80\" placeholder=\"my-project\"><small>Строчные латинские буквы, цифры и дефис. После сохранения не меняется.</small></label><label>Категория<select name=\"category\"><option value=\"web\">Web</option><option value=\"design\">Design / Photo</option><option value=\"video\">Video</option></select></label><label>Статус<select name=\"status\"><option value=\"draft\">Черновик — только мне</option><option value=\"published\">Опубликован</option><option value=\"hidden\">Скрыт — только мне</option></select></label><label>Порядок<input type=\"number\" name=\"position\" value=\"0\" min=\"0\" max=\"10000\" step=\"1\" required></label></div>\r\n<div class=\"field-grid\"><label>Название · EN<input name=\"title_en\" maxlength=\"160\" required></label><label>Название · RU<input name=\"title_ru\" maxlength=\"160\"></label><label>Подпись карточки · EN<textarea name=\"description_en\" maxlength=\"500\" rows=\"2\"></textarea></label><label>Подпись карточки · RU<textarea name=\"description_ru\" maxlength=\"500\" rows=\"2\"></textarea></label><label>Результат · EN<textarea name=\"result_en\" maxlength=\"6000\" rows=\"5\"></textarea></label><label>Результат · RU<textarea name=\"result_ru\" maxlength=\"6000\" rows=\"5\"></textarea></label></div>\r\n<label>Инструменты / технологии<input name=\"tech\" maxlength=\"300\" placeholder=\"Lightroom / Photoshop\"></label><label class=\"check\"><input type=\"checkbox\" name=\"concept\"> Это концепция, а не завершённая работа клиента</label>\r\n<h3>Обложка</h3><input type=\"hidden\" name=\"cover\"><label>Загрузить обложку · JPEG, PNG, WebP до 10 МБ<input id=\"cover-upload\" type=\"file\" accept=\"image/jpeg,image/png,image/webp\"></label><img id=\"cover-preview\" class=\"cover-preview\" alt=\"Обложка\" hidden>\r\n<h3>Фотографии результата</h3><label>Добавить фотографии · до 24 в галерее<input id=\"gallery-upload\" type=\"file\" multiple accept=\"image/jpeg,image/png,image/webp\"></label><div id=\"gallery-editor\" class=\"gallery-editor\"></div>\r\n<div class=\"field-grid\"><label>Видео · ссылка на YouTube или Vimeo<input name=\"video\" type=\"url\" placeholder=\"https://www.youtube.com/watch?v=…\"></label><label>Ссылка на готовый сайт (необязательно)<input name=\"link\" type=\"url\" placeholder=\"https://…\"></label></div><p id=\"editor-status\" role=\"status\"></p><div class=\"sticky-actions\"><button type=\"submit\" class=\"primary\" id=\"save-project\">Сохранить</button><a id=\"preview-project\" href=\"#\" target=\"_blank\" rel=\"noopener\" hidden>Посмотреть сохранённую версию ↗</a></div></form></dialog>\r\n</body></html>\r\n";
var default_settings_default = {
	contacts: {
		"telegram": "https://t.me/qwelskw211",
		"email": "qwelskw211@gmail.com",
		"github": "https://github.com/23DP3DBesp",
		"instagram": "https://www.instagram.com/qwelskw211/"
	},
	copy: {}
};
var copy_defaults_default = {
	"Skip to content": "Перейти к содержимому",
	"AVAILABLE FOR FREELANCE · 2026": "ОТКРЫТ К ПРОЕКТАМ · 2026",
	HOME: "ГЛАВНАЯ",
	ABOUT: "ОБО МНЕ",
	PROJECTS: "ПРОЕКТЫ",
	SKILLS: "НАВЫКИ",
	CONTACT: "КОНТАКТЫ",
	Home: "Главная",
	About: "Обо мне",
	Projects: "Проекты",
	Skills: "Навыки",
	Contact: "Контакты",
	PORTFOLIO: "ПОРТФОЛИО",
	"WEB DEVELOPER,": "ВЕБ-РАЗРАБОТЧИК,",
	"DESIGNER & VIDEO MAKER": "ДИЗАЙНЕР И ВИДЕОГРАФ",
	"DESIGN WITH INTENT.": "ДИЗАЙН СО СМЫСЛОМ.",
	"BUILD WITH CARE.": "ВНИМАНИЕ К ДЕТАЛЯМ.",
	"TELL A STORY.": "ИСТОРИИ В КАЖДОМ КАДРЕ.",
	"VIEW PROJECTS": "СМОТРЕТЬ РАБОТЫ",
	"CONTACT ME": "СВЯЗАТЬСЯ",
	PERSONAL: "ЛИЧНОЕ",
	"INDEPENDENT CREATIVE / EUROPE": "НЕЗАВИСИМЫЙ АВТОР / ЕВРОПА",
	"WEB DEVELOPMENT": "СОЗДАНИЕ САЙТОВ",
	"Modern responsive": "Современные адаптивные",
	interfaces: "интерфейсы",
	"VIDEO EDITING": "ВИДЕОМОНТАЖ",
	"Editing, color &": "Монтаж, цвет и",
	"motion graphics": "моушн-дизайн",
	VIDEOGRAPHY: "ВИДЕОСЪЁМКА",
	"Filming &": "Съёмка и",
	"visual storytelling": "визуальные истории",
	PHOTOGRAPHY: "ФОТОУСЛУГИ",
	"Photo shoots, retouching": "Фотосъёмка, ретушь",
	"& color grading": "и цветокоррекция",
	"VIEW SKILLS →": "НАВЫКИ →",
	"VIEW WORK →": "РАБОТЫ →",
	"EXPLORE →": "СМОТРЕТЬ →",
	"THE PERSON BEHIND THE WORK": "КТО СТОИТ ЗА РАБОТАМИ",
	"DESIGN.": "ДИЗАЙН.",
	"DEVELOP.": "РАЗРАБОТКА.",
	"CREATE.": "ТВОРЧЕСТВО.",
	"I'm a web developer, designer and video maker creating thoughtful digital experiences — on the web and on screen.": "Я веб-разработчик, дизайнер и видеограф. Создаю продуманные цифровые проекты — в интернете и на экране.",
	"I bring together code, visual design and storytelling to turn ideas into websites, photographs and videos.": "Объединяю код, дизайн и визуальный рассказ, чтобы превращать идеи в сайты, фотографии и видео.",
	"DISCOVER MY STORY": "БОЛЬШЕ ОБО МНЕ",
	"01 — A MIND FOR DETAIL.": "01 — ВНИМАНИЕ К ДЕТАЛЯМ.",
	"Structure & style": "Структура и стиль",
	"Interactive experiences": "Интерактивные интерфейсы",
	"Visual design & editing": "Дизайн и обработка",
	"Motion graphics & video": "Анимация и видео",
	"Photo editing & color grading": "Обработка фото и цвет",
	"Version control": "Контроль версий",
	"SELECTED PROJECTS": "ИЗБРАННЫЕ РАБОТЫ",
	"VIEW ALL PROJECTS": "ВСЕ РАБОТЫ",
	ALL: "ВСЕ",
	VIDEO: "ВИДЕО",
	"Email ↗": "Почта ↗",
	Design: "Дизайн",
	Video: "Видео",
	"NEW STORIES ARE COMING.": "НОВЫЕ ИСТОРИИ СКОРО.",
	"Video work will appear here soon. Have a filming or editing project in mind?": "Здесь скоро появятся видеоработы. Нужна съёмка или монтаж?",
	"LET’S TALK": "ОБСУДИМ ПРОЕКТ",
	"A selection of project concepts & development explorations.": "Подборка концепций и экспериментов в разработке и дизайне.",
	"AI powered product catalog": "Каталог товаров с ИИ",
	"Modern web music experience": "Современный веб-плеер",
	"Full stack project": "Full stack приложение",
	"UI and frontend experiments": "Эксперименты с интерфейсами",
	"VIEW PROJECT": "ОТКРЫТЬ ПРОЕКТ",
	"FEATURED CASE / 01": "ГЛАВНЫЙ ПРОЕКТ / 01",
	"FEATURED PROJECT — E-CATALOG": "ГЛАВНЫЙ ПРОЕКТ — E-CATALOG",
	"SMART.": "УМНО.",
	"FAST.": "БЫСТРО.",
	"SIMPLE.": "ПРОСТО.",
	"A product discovery concept that makes complex choices feel simple. A focused catalog experience, designed around the way people search.": "Концепция каталога, которая упрощает сложный выбор. Удобный поиск товаров, построенный вокруг потребностей человека.",
	TECHNOLOGIES: "ТЕХНОЛОГИИ",
	"LIVE DEMO": "О ПРОЕКТЕ",
	"YEARS LEARNING": "ГОДА ОБУЧЕНИЯ",
	PASSION: "УВЛЕЧЁННОСТЬ",
	"HAVE SOMETHING IN MIND?": "ЕСТЬ ИДЕЯ?",
	"LET'S": "ДАВАЙТЕ",
	BUILD: "СОЗДАДИМ",
	"SOMETHING.": "ЧТО-ТО НОВОЕ.",
	"A website, a photo shoot or a video?": "Сайт, фотосессия или видео?",
	"Let's turn it into reality.": "Давайте воплотим вашу идею.",
	EMAIL: "ПОЧТА",
	"Link coming soon": "Ссылка скоро появится",
	"GET IN TOUCH": "НАПИСАТЬ МНЕ",
	"For websites, photo shoots, filming and video editing.": "Создание сайтов, фото- и видеосъёмка, монтаж.",
	"Web Developer / Designer / Video Maker": "Веб-разработчик / Дизайнер / Видеограф",
	"Digital experiences. Visual stories.": "Цифровые проекты. Визуальные истории.",
	NAVIGATION: "НАВИГАЦИЯ",
	SOCIAL: "СОЦСЕТИ",
	INFO: "ИНФОРМАЦИЯ",
	"Based in Europe": "Нахожусь в Европе",
	"Available for projects": "Открыт к проектам",
	"BACK TO TOP ↑": "НАВЕРХ ↑",
	"DESIGNED & DEVELOPED BY QWELSKW": "ДИЗАЙН И РАЗРАБОТКА — QWELSKW",
	"EXPLORE THE WORK": "НАЙДИТЕ РАБОТУ",
	"FIND A PROJECT.": "ПОИСК ПРОЕКТА.",
	"Search by name or technology": "Поиск по названию или технологии",
	"Try JavaScript or E-Catalog…": "Например, JavaScript или E-Catalog…",
	"No projects found. Try “JavaScript” or “Vue”.": "Ничего не найдено. Попробуйте JavaScript или Vue.",
	"ABOUT ME": "ОБО МНЕ",
	"THOUGHTFUL BY DESIGN.": "ОСМЫСЛЕННО В КАЖДОЙ ДЕТАЛИ.",
	"I'm Qwelskw, a web developer, designer and video maker based in Europe. I turn ideas into digital experiences and visual stories — from the first sketch to the final frame.": "Я Qwelskw — веб-разработчик, дизайнер и видеограф из Европы. Превращаю идеи в цифровые проекты и визуальные истории — от первого эскиза до последнего кадра.",
	"My work brings together three disciplines: building responsive websites, designing clear and expressive visuals, and shaping stories through video editing and motion. I approach each medium with the same attention to detail.": "Создаю адаптивные сайты и выразительный дизайн, занимаюсь фото- и видеосъёмкой, монтажом и анимацией. В каждом направлении уделяю внимание деталям.",
	"My approach is simple: understand the idea, choose the right medium and refine every detail — whether it is an interaction, a composition or a cut.": "Мой подход прост: понять идею, выбрать подходящий формат и проработать каждую деталь — взаимодействие, композицию или монтажный переход.",
	"Live demo and source code will be linked when this project is published.": "Ссылки на готовый проект и исходный код появятся после публикации.",
	"LET'S CONNECT": "БУДЕМ НА СВЯЗИ",
	"TELEGRAM.": "TELEGRAM.",
	"Qwelskw's Telegram profile hasn't been added yet.": "Ссылка на Telegram пока не добавлена.",
	"Check back soon for contact details and new project updates.": "Пока можно связаться по почте или через Instagram.",
	"A product discovery concept for a tire catalog. The interface explores natural-language search, clear product comparisons and a focused path from browsing to finding the right fit.": "Концепция каталога шин: поиск на естественном языке, наглядное сравнение товаров и удобный путь к подходящему выбору.",
	"The proposed stack connects a Vue interface to a searchable product database and an AI-assisted discovery layer.": "Предлагаемая архитектура связывает интерфейс Vue, базу товаров и поиск с поддержкой ИИ.",
	"A music player concept built around a distraction-free listening experience. Album artwork, a clear playback hierarchy and a responsive library give the music room to breathe.": "Концепция музыкального плеера без отвлекающих деталей: обложки альбомов, понятное управление и адаптивная библиотека.",
	"The design explores playlist navigation, track discovery and accessible playback controls.": "Проект исследует навигацию по плейлистам, поиск музыки и доступное управление воспроизведением.",
	"A full stack application concept bringing a structured backend and a clear frontend together. The focus is predictable navigation and readable information.": "Концепция full stack приложения с продуманным сервером и понятным интерфейсом. В центре внимания — удобная навигация и читаемость.",
	"The proposed architecture uses a .NET API, C# business logic and a SQL data layer.": "Предлагаемая архитектура использует API на .NET, логику на C# и базу данных SQL.",
	"A collection of interface explorations: typography, layout, motion and small interactions. A space to question familiar patterns and make the web feel more considered.": "Коллекция экспериментов с типографикой, сеткой, движением и небольшими взаимодействиями. Поиск новых решений для привычных интерфейсов.",
	"Built around browser-native capabilities, responsive CSS and lightweight JavaScript.": "Основано на возможностях браузера, адаптивном CSS и лёгком JavaScript.",
	"Main navigation": "Основная навигация",
	Language: "Язык",
	"Search projects": "Поиск проектов",
	"Open navigation": "Открыть меню",
	"Close navigation": "Закрыть меню",
	"Close dialog": "Закрыть окно",
	"Close search": "Закрыть поиск",
	"What I do": "Услуги",
	"Tools and skills": "Инструменты и навыки",
	"Project categories": "Категории проектов",
	"Portfolio in numbers": "Портфолио в цифрах",
	"Contact Qwelskw": "Связаться с Qwelskw",
	"Qwelskw Portfolio home": "Портфолио Qwelskw — главная",
	"Black and white editorial portrait of a creative professional": "Чёрно-белый творческий портрет",
	"Cinematic monochrome portrait at a creative workspace": "Чёрно-белый портрет за работой",
	"E-Catalog product discovery concept": "Концепция каталога E-Catalog",
	"LET’S DISCUSS YOUR PROJECT": "ОБСУДИМ ВАШ ПРОЕКТ",
	Service: "Услуга",
	"Choose a service": "Выберите услугу",
	"Website development": "Создание сайта",
	"Video filming": "Видеосъёмка",
	"Video editing": "Видеомонтаж",
	Photography: "Фотоуслуги",
	"Tell me about your project": "Расскажите о задаче",
	"How can I reach you?": "Как с вами связаться?",
	"Email, Telegram or phone": "Почта, Telegram или телефон",
	"Your details are used only to respond to this request.": "Ваши контакты нужны только для ответа на эту заявку.",
	"SEND REQUEST": "ОТПРАВИТЬ ЗАЯВКУ",
	"VIEW RESULT": "СМОТРЕТЬ РЕЗУЛЬТАТ",
	"Sending…": "Отправляю…",
	"Request sent. I’ll get back to you using the contact you provided.": "Заявка отправлена. Я отвечу по указанному вами контакту.",
	"Could not send. Please try again or contact me directly.": "Не удалось отправить. Попробуйте ещё раз или напишите мне напрямую."
};
//#endregion
//#region server/worker.js
var json = (data, status = 200) => new Response(JSON.stringify(data), {
	status,
	headers: {
		"Content-Type": "application/json; charset=utf-8",
		"Cache-Control": "no-store",
		"X-Content-Type-Options": "nosniff"
	}
});
var fail = (message, status = 400, field) => {
	throw Object.assign(new Error(message), {
		status,
		field
	});
};
var stmt = (env, sql, ...args) => env.DB.prepare(sql).bind(...args);
var now = () => (/* @__PURE__ */ new Date()).toISOString();
var idPattern = /^[a-z0-9][a-z0-9-]{0,79}$/;
function text(value, max = 5e3) {
	if (typeof value !== "string" || value.length > max) fail("Invalid text / Некорректный текст");
	return value.trim();
}
function bilingual(value, max) {
	return {
		en: text(value?.en ?? "", max),
		ru: text(value?.ru ?? "", max)
	};
}
function safeURL(value, { image = false, video = false } = {}) {
	value = text(value ?? "", 2e3);
	if (!value) return "";
	if (image) {
		if (/^\/(assets\/images\/[a-zA-Z0-9._-]+|media\/[a-z0-9-]+)$/.test(value)) return value;
		fail("Upload an image / Загрузите изображение");
	}
	let u;
	try {
		u = new URL(value);
	} catch {
		fail("Invalid URL / Некорректная ссылка");
	}
	if (u.protocol !== "https:" || u.username || u.password) fail("Use an HTTPS link / Используйте HTTPS");
	if (video && ![
		"youtube.com",
		"www.youtube.com",
		"youtu.be",
		"vimeo.com",
		"www.vimeo.com"
	].includes(u.hostname)) fail("Use a YouTube or Vimeo link");
	return u.href;
}
function validateProject(value) {
	if (typeof value.id !== "string" || !idPattern.test(value.id.trim())) fail("Адрес работы: используйте от 1 до 80 строчных латинских букв, цифр и дефисов. Начните с буквы или цифры. Например: my-project.", 400, "id");
	if (![
		"web",
		"design",
		"video"
	].includes(value.category)) fail("Выберите категорию: Web, Design / Photo или Video.", 400, "category");
	if (![
		"draft",
		"published",
		"hidden"
	].includes(value.status)) fail("Выберите статус: черновик, опубликован или скрыт.", 400, "status");
	if (!["number", "string"].includes(typeof value.position) || String(value.position).trim() === "" || !Number.isInteger(Number(value.position)) || Number(value.position) < 0 || Number(value.position) > 1e4) fail("Порядок: укажите целое число от 0 до 10000, например 0.", 400, "position");
	const p = {
		id: text(value.id, 80),
		category: text(value.category, 16),
		status: text(value.status, 16),
		position: Number(value.position),
		title: bilingual(value.title, 160),
		description: bilingual(value.description, 500),
		result: bilingual(value.result, 6e3),
		cover: safeURL(value.cover, { image: true }),
		gallery: [],
		video: safeURL(value.video, { video: true }),
		link: safeURL(value.link),
		tech: text(value.tech ?? "", 300),
		concept: value.concept === true
	};
	if (!Array.isArray(value.gallery) || value.gallery.length > 24) fail("Maximum 24 gallery images");
	p.gallery = value.gallery.map((x) => safeURL(x, { image: true }));
	if (p.status === "published" && (!p.title.en || !p.title.ru || !p.cover || !p.result.en && !p.video && !p.gallery.length)) fail("Publishing requires EN/RU titles, a cover and a result / Для публикации нужны названия EN/RU, обложка и результат");
	return p;
}
async function init(env) {
	if (await stmt(env, "SELECT id FROM settings WHERE id=1").first()) return;
	const operations = seed_default.map((p) => stmt(env, "INSERT OR IGNORE INTO projects (id,data,status,position,revision,updated) SELECT ?,?,?,?,1,? WHERE NOT EXISTS (SELECT 1 FROM settings WHERE id=1)", p.id, JSON.stringify(p), p.status, p.position, now()));
	operations.push(stmt(env, "INSERT OR IGNORE INTO settings (id,data,revision) VALUES (1,?,1)", JSON.stringify(default_settings_default)));
	await env.DB.batch(operations);
}
async function identity(request, env) {
	if (passwordMode(env)) return passwordIdentity(request, env);
	const id = request.headers.get("oai-authenticated-user-id"), email = request.headers.get("oai-authenticated-user-email");
	if (!id || !email) return null;
	const existing = await stmt(env, "SELECT user_id FROM owner WHERE id=1").first();
	if (existing) return existing.user_id === id ? {
		id,
		email
	} : null;
	if (!env.ADMIN_OWNER_EMAIL || email.toLowerCase() !== env.ADMIN_OWNER_EMAIL.toLowerCase()) return null;
	await stmt(env, "INSERT OR IGNORE INTO owner (id,user_id) VALUES (1,?)", id).run();
	return (await stmt(env, "SELECT user_id FROM owner WHERE id=1").first())?.user_id === id ? {
		id,
		email
	} : null;
}
function sameOrigin(request) {
	if (request.headers.get("Origin") !== new URL(request.url).origin) fail("Origin rejected", 403);
	if (request.headers.get("Sec-Fetch-Site") === "cross-site") fail("Cross-site request rejected", 403);
}
async function body(request, max = 1e5) {
	if (Number(request.headers.get("Content-Length")) > max) fail("Request too large", 413);
	const reader = request.body?.getReader();
	if (!reader) fail("Missing body");
	const chunks = [];
	let size = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.length;
		if (size > max) {
			await reader.cancel();
			fail("Request too large", 413);
		}
		chunks.push(value);
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.length;
	}
	let value;
	try {
		value = JSON.parse(new TextDecoder().decode(bytes));
	} catch {
		fail("Invalid JSON");
	}
	if (!value || Array.isArray(value) || typeof value !== "object") fail("Expected a JSON object");
	return value;
}
async function upload(request, env) {
	const type = request.headers.get("Content-Type")?.split(";")[0];
	if (![
		"image/jpeg",
		"image/png",
		"image/webp"
	].includes(type)) fail("JPEG, PNG or WebP only");
	if (Number(request.headers.get("Content-Length")) > 10485760) fail("Image limit: 10 MB", 413);
	const reader = request.body?.getReader();
	if (!reader) fail("Empty image");
	let total = 0, chunks = [];
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.length;
		if (total > 10485760) {
			await reader.cancel();
			fail("Image limit: 10 MB", 413);
		}
		chunks.push(value);
	}
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.length;
	}
	const png = bytes[0] === 137 && bytes[1] === 80 && bytes[2] === 78 && bytes[3] === 71;
	const jpg = bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255;
	const webp = new TextDecoder().decode(bytes.slice(0, 4)) === "RIFF" && new TextDecoder().decode(bytes.slice(8, 12)) === "WEBP";
	if (!(type === "image/png" && png || type === "image/jpeg" && jpg || type === "image/webp" && webp)) fail("File content does not match image type");
	const id = crypto.randomUUID();
	await env.MEDIA.put(id, bytes, { httpMetadata: { contentType: type } });
	try {
		await stmt(env, "INSERT INTO media (id,type,name,created) VALUES (?,?,?,?)", id, type, "image", now()).run();
	} catch (e) {
		await env.MEDIA.delete(id);
		throw e;
	}
	return json({ url: `/media/${id}` }, 201);
}
async function inquiry(request, env) {
	sameOrigin(request);
	const value = await body(request, 12e3);
	if (value.website) return json({ ok: true });
	const service = text(value.service, 50), description = text(value.description, 4e3), contact = text(value.contact, 300);
	if (![
		"web",
		"design",
		"filming",
		"editing",
		"photo"
	].includes(service) || description.length < 10 || contact.length < 3) fail("Complete all fields / Заполните все поля");
	const date = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10), ip = request.headers.get("CF-Connecting-IP") || "unknown";
	const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${date}:${ip}`));
	if ((await stmt(env, "INSERT INTO rate_limits (key,count,expires) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count", Array.from(new Uint8Array(hash), (x) => x.toString(16).padStart(2, "0")).join(""), Date.now() + 864e5).first()).count > 5) fail("Please try tomorrow / Попробуйте завтра", 429);
	await env.DB.batch([stmt(env, "INSERT INTO inquiries (id,service,description,contact,status,created) VALUES (?,?,?,?,?,?)", crypto.randomUUID(), service, description, contact, "new", now()), stmt(env, "DELETE FROM rate_limits WHERE expires < ?", Date.now())]);
	return json({ ok: true }, 201);
}
async function handle(request, env) {
	const url = new URL(request.url), path = url.pathname, method = request.method;
	if (path.startsWith("/api/") || path.startsWith("/media/") || path === "/admin" || path.startsWith("/admin/")) {
		if (!env.DB) fail("Database is unavailable", 503);
		await init(env);
	}
	const authResponse = await authRoute(request, env, {
		json,
		fail,
		body,
		sameOrigin
	});
	if (authResponse) return authResponse;
	if (path === "/api/content" && method === "GET") {
		const result = await stmt(env, "SELECT data FROM projects WHERE status='published' ORDER BY position,id").all();
		const settings = await stmt(env, "SELECT data FROM settings WHERE id=1").first();
		return json({
			projects: result.results.map((r) => JSON.parse(r.data)),
			settings: JSON.parse(settings.data)
		});
	}
	if (path === "/api/inquiries" && method === "POST") return inquiry(request, env);
	if (path.startsWith("/media/") && method === "GET") {
		const key = path.slice(7);
		if (!/^[a-f0-9-]{36}$/.test(key)) fail("Not found", 404);
		if (!(await stmt(env, "SELECT data FROM projects WHERE status='published'").all()).results.some((r) => {
			const p = JSON.parse(r.data);
			return p.cover === path || p.gallery?.includes(path);
		}) && !await identity(request, env)) fail("Not found", 404);
		const object = await env.MEDIA.get(key);
		if (!object) fail("Not found", 404);
		return new Response(object.body, { headers: {
			"Content-Type": object.httpMetadata?.contentType || "application/octet-stream",
			"Cache-Control": "no-store",
			"X-Content-Type-Options": "nosniff"
		} });
	}
	if (path === "/admin" || path === "/admin/" || path.startsWith("/api/admin")) {
		const user = await identity(request, env);
		if (!user) {
			if (path.startsWith("/api/")) return json({ error: "Owner access required / Доступ только владельцу" }, request.headers.get("oai-authenticated-user-id") ? 403 : 401);
			if (passwordMode(env)) return Response.redirect(`${url.origin}/admin/login`, 302);
			if (!request.headers.get("oai-authenticated-user-id")) return Response.redirect(`${url.origin}/signin-with-chatgpt?return_to=%2Fadmin`, 302);
			return new Response("Доступ только владельцу сайта. Войдите в свой аккаунт ChatGPT.", {
				status: 403,
				headers: {
					"Content-Type": "text/plain; charset=utf-8",
					"Cache-Control": "no-store"
				}
			});
		}
		if (path === "/admin" || path === "/admin/") {
			const [rows, setting] = await Promise.all([stmt(env, "SELECT * FROM projects ORDER BY position,id").all(), stmt(env, "SELECT * FROM settings WHERE id=1").first()]);
			const bootstrap = JSON.stringify({
				session: {
					email: user.email,
					passwordAuth: passwordMode(env)
				},
				projects: rows.results.map((r) => ({
					...JSON.parse(r.data),
					revision: r.revision
				})),
				settings: {
					...JSON.parse(setting.data),
					revision: setting.revision
				},
				copyDefaults: copy_defaults_default
			}).replace(/</g, "\\u003c");
			const page = passwordMode(env) ? admin_default.replace("/signin-with-chatgpt?return_to=%2Fadmin", "/admin/login").replace("<a href=\"/signout-with-chatgpt?return_to=/\">Выйти</a>", "<form action=\"/api/auth/logout\" method=\"post\" class=\"logout-form\"><button type=\"submit\">Выйти</button></form>") : admin_default;
			return new Response(page.replace("<!--ADMIN_BOOTSTRAP-->", () => `<script type="application/json" id="admin-bootstrap">${bootstrap}<\/script>`), { headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store",
				"Content-Security-Policy": "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'"
			} });
		}
		if (method !== "GET") sameOrigin(request);
		if (path === "/api/admin/copy-defaults" && method === "GET") return json(copy_defaults_default);
		if (path === "/api/admin/session") return json({ email: user.email });
		if (path === "/api/admin/projects" && method === "GET") return json((await stmt(env, "SELECT * FROM projects ORDER BY position,id").all()).results.map((r) => ({
			...JSON.parse(r.data),
			revision: r.revision
		})));
		if (path === "/api/admin/projects" && method === "DELETE") {
			const value = await body(request, 1e3), id = text(value.id, 80);
			if (!idPattern.test(id) || !Number.isInteger(value.revision) || value.revision < 1) fail("Некорректные данные проекта");
			const prior = await stmt(env, "SELECT revision FROM projects WHERE id=?", id).first();
			if (!prior) fail("Работа уже удалена. Обновите список.", 404);
			if (prior.revision !== value.revision) fail("Работа изменена в другой вкладке. Обновите страницу перед удалением.", 409);
			if (!(await stmt(env, "DELETE FROM projects WHERE id=? AND revision=?", id, value.revision).run()).meta.changes) fail("Работа изменилась. Обновите страницу перед удалением.", 409);
			return json({ ok: true });
		}
		if (path === "/api/admin/projects" && method === "POST") {
			const value = await body(request), p = validateProject(value);
			const prior = await stmt(env, "SELECT revision FROM projects WHERE id=?", p.id).first();
			if (prior) {
				if (value.revision !== prior.revision) fail("Changed in another tab. Reload first. / Изменено в другой вкладке. Обновите страницу.", 409);
				if (!(await stmt(env, "UPDATE projects SET data=?,status=?,position=?,revision=revision+1,updated=? WHERE id=? AND revision=?", JSON.stringify(p), p.status, p.position, now(), p.id, value.revision).run()).meta.changes) fail("Conflict / Конфликт изменений", 409);
			} else {
				if (value.revision) fail("Project missing", 409);
				await stmt(env, "INSERT INTO projects (id,data,status,position,revision,updated) VALUES (?,?,?,?,1,?)", p.id, JSON.stringify(p), p.status, p.position, now()).run();
			}
			return json({ ok: true });
		}
		if (path === "/api/admin/settings" && method === "GET") {
			const r = await stmt(env, "SELECT * FROM settings WHERE id=1").first();
			return json({
				...JSON.parse(r.data),
				revision: r.revision
			});
		}
		if (path === "/api/admin/settings" && method === "POST") {
			const value = await body(request, 25e4);
			const contacts = {};
			for (const key of [
				"telegram",
				"instagram",
				"github"
			]) contacts[key] = safeURL(value.contacts?.[key]);
			contacts.email = text(value.contacts?.email ?? "", 254);
			if (contacts.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contacts.email)) fail("Invalid email");
			const copy = {};
			if (!value.copy || Array.isArray(value.copy) || typeof value.copy !== "object" || Object.keys(value.copy).length > 300) fail("Invalid copy");
			for (const [key, val] of Object.entries(value.copy)) {
				if (key.length > 7e3 || [
					"__proto__",
					"constructor",
					"prototype"
				].includes(key)) fail("Invalid key");
				copy[key] = bilingual(val, 7e3);
			}
			if (!(await stmt(env, "UPDATE settings SET data=?,revision=revision+1 WHERE id=1 AND revision=?", JSON.stringify({
				contacts,
				copy
			}), Number(value.revision)).run()).meta.changes) fail("Settings changed. Reload first. / Настройки изменились. Обновите страницу.", 409);
			return json({ ok: true });
		}
		if (path === "/api/admin/upload" && method === "POST") return upload(request, env);
		if (path === "/api/admin/inquiries" && method === "GET") return json((await stmt(env, "SELECT * FROM inquiries ORDER BY created DESC LIMIT 300").all()).results);
		if (path === "/api/admin/inquiries" && method === "POST") {
			const value = await body(request);
			if (![
				"new",
				"read",
				"done"
			].includes(value.status)) fail("Invalid status");
			await stmt(env, "UPDATE inquiries SET status=? WHERE id=?", value.status, text(value.id, 80)).run();
			return json({ ok: true });
		}
		if (path.startsWith("/api/admin/projects/") && method === "GET") {
			const r = await stmt(env, "SELECT data FROM projects WHERE id=?", path.split("/").pop()).first();
			if (!r) fail("Not found", 404);
			return json(JSON.parse(r.data));
		}
		fail("Not found", 404);
	}
	if (path.startsWith("/api/")) fail("Not found", 404);
	if (path === "/work" || path === "/work/") return asset(request, env, "/work/index.html");
	if (path.startsWith("/admin/")) fail("Not found", 404);
	return asset(request, env, path === "/" ? "/index.html" : path);
}
async function asset(request, env, path, privatePage = false) {
	if (!env.ASSETS) fail("Assets unavailable", 503);
	const url = new URL(request.url);
	url.pathname = path;
	url.search = "";
	const response = await env.ASSETS.fetch(new Request(url, request));
	const result = new Response(response.body, response);
	if (privatePage) result.headers.set("Cache-Control", "no-store");
	return result;
}
var worker_default = { async fetch(request, env) {
	try {
		const raw = await handle(request, env);
		const response = new Response(raw.body, raw);
		response.headers.set("X-Content-Type-Options", "nosniff");
		response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
		return response;
	} catch (error) {
		return json({
			error: error.status ? error.message : "Server error / Ошибка сервера",
			...error.status && error.field ? { field: error.field } : {}
		}, error.status || 500);
	}
} };
//#endregion
export { worker_default as default, safeURL, validateProject };
