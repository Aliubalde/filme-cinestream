import 'dotenv/config';
import { resolveMx } from 'node:dns/promises';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';
import express, { NextFunction, Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { Movie } from './src/types.ts';
import { INITIAL_MOVIES, MASTER_EMAIL } from './src/data/initialData.ts';

const app = express();
const port = Number(process.env.PORT || 3000);
const maxVideoBytes = 4 * 1024 * 1024 * 1024;
const dataDirectory = path.resolve(process.env.MEDIA_DIR || 'data');
const mediaDirectory = path.join(dataDirectory, 'media');
const catalogPath = path.join(dataDirectory, 'catalog.json');
const ownersPath = path.join(dataDirectory, 'owners.json');
const ownerCredentialsPath = path.join(dataDirectory, 'owner-credentials.json');
const accountsPath = path.join(dataDirectory, 'accounts.json');
const visitorsPath = path.join(dataDirectory, 'visitors.json');
const settingsPath = path.join(dataDirectory, 'access-settings.json');
const socialLinksPath = path.join(dataDirectory, 'social-links.json');
const titleRequestsPath = path.join(dataDirectory, 'title-requests.json');
const allowedEmails = (process.env.ADMIN_EMAILS || MASTER_EMAIL)
  .split(',')
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);
const pendingUploads = new Map<string, { movieData: Omit<Movie, 'id' | 'createdAt'>; extension: string }>();

await mkdir(mediaDirectory, { recursive: true });
app.use(express.json({ limit: '10mb' }));

const readOwners = async (): Promise<string[]> => {
  try {
    const owners: unknown = JSON.parse(await readFile(ownersPath, 'utf8'));
    if (Array.isArray(owners)) {
      return Array.from(new Set([MASTER_EMAIL.toLowerCase(), ...owners.map((email) => String(email).toLowerCase())]));
    }
  } catch {
    // Initialize the shared owner list from server configuration.
  }
  await writeFile(ownersPath, JSON.stringify(allowedEmails, null, 2));
  return Array.from(new Set([MASTER_EMAIL.toLowerCase(), ...allowedEmails]));
};

interface OwnerCredential {
  email: string;
  salt: string;
  passwordHash: string;
  createdAt: number;
}

const readOwnerCredentials = async (): Promise<OwnerCredential[]> => {
  try {
    const credentials: unknown = JSON.parse(await readFile(ownerCredentialsPath, 'utf8'));
    return Array.isArray(credentials) ? credentials as OwnerCredential[] : [];
  } catch {
    return [];
  }
};

const writeOwnerCredentials = (credentials: OwnerCredential[]) => writeJsonFile(ownerCredentialsPath, credentials);

const validateAdminCredentials = async (email: string, password: string) => {
  if (!(await readOwners()).includes(email)) return false;
  if (email === MASTER_EMAIL.toLowerCase()) {
    return Boolean(process.env.ADMIN_PASSWORD) && passwordsMatch(password, process.env.ADMIN_PASSWORD || '');
  }

  const credential = (await readOwnerCredentials()).find((item) => item.email === email);
  if (!credential) return false;
  const suppliedHash = scryptSync(password, credential.salt, 64);
  const savedHash = Buffer.from(credential.passwordHash, 'hex');
  return savedHash.length === suppliedHash.length && timingSafeEqual(suppliedHash, savedHash);
};

const emailDomainHasMx = async (email: string) => {
  const domain = email.split('@')[1];
  try {
    return (await resolveMx(domain)).length > 0;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND' || code === 'ESERVFAIL') return false;
    throw error;
  }
};

const passwordsMatch = (provided: string, configured: string) => {
  const providedBuffer = Buffer.from(provided);
  const configuredBuffer = Buffer.from(configured);
  return providedBuffer.length === configuredBuffer.length && timingSafeEqual(providedBuffer, configuredBuffer);
};

const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  const email = String(req.header('x-admin-email') || '').trim().toLowerCase();
  const password = req.header('x-admin-password') || '';
  if (!process.env.ADMIN_PASSWORD) {
    res.status(503).json({ error: 'Configure ADMIN_PASSWORD no arquivo .env para habilitar o painel restrito.' });
    return;
  }

  void validateAdminCredentials(email, password).then((isValid) => {
    if (!isValid) {
      res.status(401).json({ error: 'E-mail ou senha do painel restrito inválidos.' });
      return;
    }
    next();
  }).catch(next);
};

const requireMaster = (req: Request, res: Response, next: NextFunction) => {
  if (String(req.header('x-admin-email') || '').trim().toLowerCase() !== MASTER_EMAIL.toLowerCase()) {
    res.status(403).json({ error: 'Somente o dono mestre pode administrar outros donos.' });
    return;
  }
  next();
};

const readCatalog = async (): Promise<Movie[]> => {
  try {
    const contents = await readFile(catalogPath, 'utf8');
    const parsed: unknown = JSON.parse(contents);
    return Array.isArray(parsed) ? parsed as Movie[] : INITIAL_MOVIES;
  } catch {
    await writeFile(catalogPath, JSON.stringify(INITIAL_MOVIES, null, 2));
    return INITIAL_MOVIES;
  }
};

interface PublicAccount {
  id: string;
  email: string;
  name: string;
  salt: string;
  passwordHash: string;
  createdAt: number;
  lastLoginAt: number | null;
  expiresAt: number | null;
  revokedAt: number | null;
  favorites: number[];
  activities: AccountActivity[];
}

interface AccountActivity {
  id: string;
  type: 'account_created' | 'login' | 'watch' | 'favorite' | 'unfavorite' | 'request';
  description: string;
  createdAt: number;
}

interface TitleRequest {
  id: string;
  accountId: string;
  email: string;
  title: string;
  kind: 'Filme' | 'Série';
  details: string;
  status: 'Pendente' | 'Em análise' | 'Atendido' | 'Recusado';
  createdAt: number;
}

interface SocialLinks {
  telegram: string;
  instagram: string;
  whatsapp: string;
  facebook: string;
}

const emptySocialLinks: SocialLinks = { telegram: '', instagram: '', whatsapp: '', facebook: '' };

interface VisitorAccess {
  id: string;
  email: string;
  name: string;
  guestPass: string;
  createdAt: number;
  pendingUntil: number;
  expiresAt: number | null;
  revokedAt: number | null;
}

interface AccessSettings {
  guestMinutes: number;
}

const readAccounts = async (): Promise<PublicAccount[]> => {
  try {
    const stored: unknown = JSON.parse(await readFile(accountsPath, 'utf8'));
    if (!Array.isArray(stored)) return [];
    const accounts = stored.map((item) => {
      const account = item as Partial<PublicAccount>;
      return {
        ...account,
        id: account.id || randomUUID(),
        createdAt: account.createdAt || Date.now(),
        lastLoginAt: account.lastLoginAt ?? null,
        expiresAt: account.expiresAt ?? null,
        revokedAt: account.revokedAt ?? null,
        favorites: account.favorites ?? [],
        activities: account.activities ?? [],
      } as PublicAccount;
    });
    await writeAccounts(accounts);
    return accounts;
  } catch {
    return [];
  }
};

const writeJsonFile = async (filePath: string, value: unknown) => {
  const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, JSON.stringify(value, null, 2));
  await rename(temporaryPath, filePath);
};

const writeAccounts = (accounts: PublicAccount[]) => writeJsonFile(accountsPath, accounts);

const readVisitors = async (): Promise<VisitorAccess[]> => {
  try {
    const visitors: unknown = JSON.parse(await readFile(visitorsPath, 'utf8'));
    return Array.isArray(visitors) ? visitors as VisitorAccess[] : [];
  } catch {
    return [];
  }
};

const writeVisitors = (visitors: VisitorAccess[]) => writeJsonFile(visitorsPath, visitors);

const readAccessSettings = async (): Promise<AccessSettings> => {
  try {
    const settings = JSON.parse(await readFile(settingsPath, 'utf8')) as Partial<AccessSettings>;
    return { guestMinutes: Math.min(1440, Math.max(1, Number(settings.guestMinutes) || 30)) };
  } catch {
    return { guestMinutes: 30 };
  }
};

const publicAccountResponse = (account: PublicAccount) => ({
  accountId: account.id,
  email: account.email,
  name: account.name,
  avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(account.email)}`,
  favorites: account.favorites,
  expiresAt: account.expiresAt,
});

const addActivity = (account: PublicAccount, type: AccountActivity['type'], description: string) => {
  account.activities = [
    { id: randomUUID(), type, description, createdAt: Date.now() },
    ...(account.activities || []),
  ].slice(0, 200);
};

const readSocialLinks = async (): Promise<SocialLinks> => {
  try {
    return { ...emptySocialLinks, ...JSON.parse(await readFile(socialLinksPath, 'utf8')) };
  } catch {
    return emptySocialLinks;
  }
};

const readTitleRequests = async (): Promise<TitleRequest[]> => {
  try {
    const requests: unknown = JSON.parse(await readFile(titleRequestsPath, 'utf8'));
    return Array.isArray(requests) ? requests as TitleRequest[] : [];
  } catch {
    return [];
  }
};

app.get('/api/public/social-links', async (_req, res, next) => {
  try {
    res.json(await readSocialLinks());
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/social-links', requireAdmin, requireMaster, async (_req, res, next) => {
  try {
    res.json(await readSocialLinks());
  } catch (error) {
    next(error);
  }
});

app.put('/api/admin/social-links', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const socialLinks: SocialLinks = { ...emptySocialLinks };
    for (const key of Object.keys(socialLinks) as (keyof SocialLinks)[]) {
      const rawValue = String(req.body?.[key] || '').trim();
      if (!rawValue) continue;
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(rawValue);
      } catch {
        res.status(400).json({ error: `O link de ${key} não é uma URL válida.` });
        return;
      }
      if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
        res.status(400).json({ error: `O link de ${key} precisa começar com http:// ou https://.` });
        return;
      }
      socialLinks[key] = parsedUrl.toString();
    }
    await writeJsonFile(socialLinksPath, socialLinks);
    res.json(socialLinks);
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/title-requests', requireAdmin, requireMaster, async (_req, res, next) => {
  try {
    res.json(await readTitleRequests());
  } catch (error) {
    next(error);
  }
});

app.post('/api/public/accounts/:id/requests', async (req, res, next) => {
  try {
    const accounts = await readAccounts();
    const account = accounts.find((candidate) => candidate.id === req.params.id);
    const title = String(req.body?.title || '').trim().slice(0, 120);
    const kind = req.body?.kind;
    const details = String(req.body?.details || '').trim().slice(0, 500);
    if (!account || account.revokedAt || (account.expiresAt !== null && account.expiresAt <= Date.now())) {
      res.status(401).json({ error: 'Entre em uma conta válida para pedir um título.' });
      return;
    }
    if (!title || (kind !== 'Filme' && kind !== 'Série')) {
      res.status(400).json({ error: 'Informe um título e escolha Filme ou Série.' });
      return;
    }

    const titleRequests = await readTitleRequests();
    const request: TitleRequest = {
      id: randomUUID(),
      accountId: account.id,
      email: account.email,
      title,
      kind,
      details,
      status: 'Pendente',
      createdAt: Date.now(),
    };
    await writeJsonFile(titleRequestsPath, [request, ...titleRequests]);
    addActivity(account, 'request', `Pediu ${kind.toLowerCase()}: ${title}`);
    await writeAccounts(accounts);
    res.status(201).json(request);
  } catch (error) {
    next(error);
  }
});

app.patch('/api/admin/title-requests/:id', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const validStatuses: TitleRequest['status'][] = ['Pendente', 'Em análise', 'Atendido', 'Recusado'];
    const status = req.body?.status as TitleRequest['status'];
    if (!validStatuses.includes(status)) {
      res.status(400).json({ error: 'Status de pedido inválido.' });
      return;
    }
    const requests = await readTitleRequests();
    const request = requests.find((item) => item.id === req.params.id);
    if (!request) {
      res.status(404).json({ error: 'Pedido não encontrado.' });
      return;
    }
    request.status = status;
    await writeJsonFile(titleRequestsPath, requests);
    res.json(request);
  } catch (error) {
    next(error);
  }
});

const publicVisitorResponse = (visitor: VisitorAccess) => ({
  visitorId: visitor.id,
  email: visitor.email,
  name: visitor.name,
  avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?q=80&w=200&auto=format&fit=crop',
  favorites: [],
  guestPass: visitor.guestPass,
  expiresAt: visitor.expiresAt,
});

app.post('/api/public/visitors', async (_req, res, next) => {
  try {
    const id = randomUUID();
    const code = randomBytes(6).toString('hex').toUpperCase();
    const visitor: VisitorAccess = {
      id,
      email: `visitante.${code.toLowerCase()}@cinestream.local`,
      name: 'Visitante CineStream',
      guestPass: `CINE-${code}`,
      createdAt: Date.now(),
      pendingUntil: Date.now() + 10 * 60 * 1000,
      expiresAt: null,
      revokedAt: null,
    };
    const visitors = await readVisitors();
    await writeVisitors([...visitors, visitor]);
    res.status(201).json(publicVisitorResponse(visitor));
  } catch (error) {
    next(error);
  }
});

app.post('/api/public/visitors/:id/activate', async (req, res, next) => {
  try {
    const visitors = await readVisitors();
    const visitor = visitors.find((candidate) => candidate.id === req.params.id);
    if (!visitor || visitor.revokedAt || visitor.pendingUntil <= Date.now() || visitor.guestPass !== req.body?.guestPass) {
      res.status(401).json({ error: 'Este acesso de visitante expirou ou não é válido. Gere outro passe.' });
      return;
    }

    const settings = await readAccessSettings();
    visitor.expiresAt = Date.now() + settings.guestMinutes * 60 * 1000;
    await writeVisitors(visitors);
    res.json(publicVisitorResponse(visitor));
  } catch (error) {
    next(error);
  }
});

app.get('/api/public/visitors/:id', async (req, res, next) => {
  try {
    const visitor = (await readVisitors()).find((candidate) => candidate.id === req.params.id);
    if (!visitor || visitor.revokedAt || !visitor.expiresAt || visitor.expiresAt <= Date.now() || visitor.guestPass !== req.header('x-guest-pass')) {
      res.status(401).json({ error: 'Este acesso de visitante foi encerrado.' });
      return;
    }
    res.json(publicVisitorResponse(visitor));
  } catch (error) {
    next(error);
  }
});

app.delete('/api/public/visitors/:id', async (req, res, next) => {
  try {
    const visitors = await readVisitors();
    const visitor = visitors.find((candidate) => candidate.id === req.params.id);
    if (!visitor || visitor.guestPass !== req.header('x-guest-pass')) {
      res.status(404).json({ error: 'Acesso de visitante não encontrado.' });
      return;
    }
    visitor.revokedAt = Date.now();
    await writeVisitors(visitors);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.post('/api/public/register', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const name = String(req.body?.name || '').trim();
    const password = String(req.body?.password || '');
    if (!/^\S+@\S+\.\S+$/.test(email) || !name || password.length < 8) {
      res.status(400).json({ error: 'Informe nome, e-mail válido e senha com pelo menos 8 caracteres.' });
      return;
    }

    if (!(await emailDomainHasMx(email))) {
      res.status(400).json({ error: 'Este domínio não possui serviço de e-mail válido. Confira o endereço informado.' });
      return;
    }

    const accounts = await readAccounts();
    if (accounts.some((account) => account.email === email)) {
      res.status(409).json({ error: 'Já existe uma conta cadastrada com este e-mail.' });
      return;
    }

    const salt = randomBytes(16).toString('hex');
    const account: PublicAccount = {
      id: randomUUID(),
      email,
      name,
      salt,
      passwordHash: scryptSync(password, salt, 64).toString('hex'),
      createdAt: Date.now(),
      lastLoginAt: Date.now(),
      expiresAt: null,
      revokedAt: null,
      favorites: [],
      activities: [],
    };
    addActivity(account, 'account_created', 'Conta criada');
    await writeAccounts([...accounts, account]);
    res.status(201).json(publicAccountResponse(account));
  } catch (error) {
    next(error);
  }
});

app.post('/api/public/login', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const accounts = await readAccounts();
    const account = accounts.find((candidate) => candidate.email === email);
    if (!account || account.revokedAt || (account.expiresAt !== null && account.expiresAt <= Date.now())) {
      res.status(401).json({ error: 'E-mail ou senha incorretos. Cadastre-se para criar uma conta.' });
      return;
    }

    const passwordHash = scryptSync(password, account.salt, 64);
    const savedHash = Buffer.from(account.passwordHash, 'hex');
    if (savedHash.length !== passwordHash.length || !timingSafeEqual(passwordHash, savedHash)) {
      res.status(401).json({ error: 'E-mail ou senha incorretos.' });
      return;
    }

    account.lastLoginAt = Date.now();
    addActivity(account, 'login', 'Entrou na conta');
    await writeAccounts(accounts);
    res.json(publicAccountResponse(account));
  } catch (error) {
    next(error);
  }
});

app.get('/api/public/accounts/:id/profile', async (req, res, next) => {
  try {
    const account = (await readAccounts()).find((candidate) => candidate.id === req.params.id);
    if (!account || account.revokedAt || (account.expiresAt !== null && account.expiresAt <= Date.now())) {
      res.status(401).json({ error: 'Esta conta foi expirada ou revogada.' });
      return;
    }
    const requests = (await readTitleRequests()).filter((request) => request.accountId === account.id);
    res.json({
      name: account.name,
      email: account.email,
      createdAt: account.createdAt,
      lastLoginAt: account.lastLoginAt,
      favorites: account.favorites,
      activities: account.activities,
        requests,
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/public/accounts/:id/activity', async (req, res, next) => {
  try {
    const accounts = await readAccounts();
    const account = accounts.find((candidate) => candidate.id === req.params.id);
    const type = String(req.body?.type || '');
    const title = String(req.body?.title || '').trim().slice(0, 160);
    if (!account || account.revokedAt || (account.expiresAt !== null && account.expiresAt <= Date.now())) {
      res.status(401).json({ error: 'Esta conta foi expirada ou revogada.' });
      return;
    }
    if (type !== 'watch' || !title) {
      res.status(400).json({ error: 'Atividade inválida.' });
      return;
    }
    addActivity(account, 'watch', `Assistiu: ${title}`);
    await writeAccounts(accounts);
    res.status(201).json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.put('/api/public/accounts/:id/favorites', async (req, res, next) => {
  try {
    const accounts = await readAccounts();
    const account = accounts.find((candidate) => candidate.id === req.params.id);
    const movieId = Number(req.body?.movieId);
    const action = req.body?.action;
    if (!account || account.revokedAt || (account.expiresAt !== null && account.expiresAt <= Date.now())) {
      res.status(401).json({ error: 'Esta conta foi expirada ou revogada.' });
      return;
    }
    if (!Number.isInteger(movieId) || !['add', 'remove'].includes(action)) {
      res.status(400).json({ error: 'Favorito inválido.' });
      return;
    }
    const alreadyFavorite = account.favorites.includes(movieId);
    if (action === 'add' && !alreadyFavorite) {
      account.favorites.unshift(movieId);
      addActivity(account, 'favorite', `Adicionou aos favoritos: ${String(req.body?.title || 'Filme').slice(0, 160)}`);
    } else if (action === 'remove' && alreadyFavorite) {
      account.favorites = account.favorites.filter((id) => id !== movieId);
      addActivity(account, 'unfavorite', `Removeu dos favoritos: ${String(req.body?.title || 'Filme').slice(0, 160)}`);
    }
    await writeAccounts(accounts);
    res.json({ favorites: account.favorites });
  } catch (error) {
    next(error);
  }
});

const writeCatalog = async (movies: Movie[]) => {
  const temporaryPath = `${catalogPath}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, JSON.stringify(movies, null, 2));
  await rename(temporaryPath, catalogPath);
};

const mediaExtension = (fileName: string) => {
  const extension = path.extname(fileName).toLowerCase();
  return ['.mp4', '.webm', '.mov', '.m4v', '.mkv', '.avi'].includes(extension) ? extension : '';
};

app.post('/api/admin/login', async (req, res, next) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!process.env.ADMIN_PASSWORD) {
    res.status(503).json({ error: 'Configure ADMIN_PASSWORD no arquivo .env para habilitar o painel restrito.' });
    return;
  }

  try {
    if (!(await validateAdminCredentials(email, password))) {
      res.status(401).json({ error: 'E-mail ou senha do painel restrito inválidos.' });
      return;
    }
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/owners', requireAdmin, requireMaster, async (_req, res, next) => {
  try {
    res.json(await readOwners());
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/owners', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) {
      res.status(400).json({ error: 'Informe um e-mail válido e uma senha com pelo menos 8 caracteres.' });
      return;
    }
    const owners = await readOwners();
    const credentials = await readOwnerCredentials();
    const salt = randomBytes(16).toString('hex');
    const credential: OwnerCredential = {
      email,
      salt,
      passwordHash: scryptSync(password, salt, 64).toString('hex'),
      createdAt: Date.now(),
    };
    const updatedCredentials = credentials.some((item) => item.email === email)
      ? credentials.map((item) => item.email === email ? credential : item)
      : [...credentials, credential];
    await writeOwnerCredentials(updatedCredentials);
    if (!owners.includes(email)) {
      await writeFile(ownersPath, JSON.stringify([...owners, email], null, 2));
    }
    res.status(201).json(await readOwners());
  } catch (error) {
    next(error);
  }
});

app.delete('/api/admin/owners', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (email === MASTER_EMAIL.toLowerCase()) {
      res.status(400).json({ error: 'O dono mestre não pode ser removido.' });
      return;
    }
    const owners = await readOwners();
    const credentials = await readOwnerCredentials();
    await writeOwnerCredentials(credentials.filter((credential) => credential.email !== email));
    await writeFile(ownersPath, JSON.stringify(owners.filter((owner) => owner !== email), null, 2));
    res.json(await readOwners());
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/access', requireAdmin, requireMaster, async (_req, res, next) => {
  try {
    const [accounts, visitors, settings] = await Promise.all([readAccounts(), readVisitors(), readAccessSettings()]);
    res.json({
      accounts: accounts.map(({ id, email, name, createdAt, lastLoginAt, expiresAt, revokedAt }) => ({
        id, email, name, createdAt, lastLoginAt, expiresAt, revokedAt,
      })),
      visitors: visitors.map(({ id, email, name, guestPass, createdAt, pendingUntil, expiresAt, revokedAt }) => ({
        id, email, name, guestPass, createdAt, pendingUntil, expiresAt, revokedAt,
      })),
      guestMinutes: settings.guestMinutes,
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/access/accounts', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const name = String(req.body?.name || '').trim();
    const password = String(req.body?.password || '');
    const durationMinutes = Number(req.body?.durationMinutes);
    if (!/^\S+@\S+\.\S+$/.test(email) || !name || password.length < 8 || !Number.isInteger(durationMinutes) || durationMinutes < 1 || durationMinutes > 525600) {
      res.status(400).json({ error: 'Informe nome, e-mail válido, senha com 8 caracteres e duração entre 1 minuto e 1 ano.' });
      return;
    }

    const accounts = await readAccounts();
    const existingAccount = accounts.find((account) => account.email === email);
    if (existingAccount && !existingAccount.revokedAt && (!existingAccount.expiresAt || existingAccount.expiresAt > Date.now())) {
      res.status(409).json({ error: 'Este e-mail já possui um acesso ativo.' });
      return;
    }

    const salt = randomBytes(16).toString('hex');
    const createdAt = Date.now();
    const account: PublicAccount = existingAccount
      ? Object.assign(existingAccount, {
          name,
          salt,
          passwordHash: scryptSync(password, salt, 64).toString('hex'),
          createdAt,
          lastLoginAt: null,
          expiresAt: createdAt + durationMinutes * 60 * 1000,
          revokedAt: null,
          favorites: existingAccount.favorites || [],
          activities: existingAccount.activities || [],
        })
      : {
          id: randomUUID(),
          email,
          name,
          salt,
          passwordHash: scryptSync(password, salt, 64).toString('hex'),
          createdAt,
          lastLoginAt: null,
          expiresAt: createdAt + durationMinutes * 60 * 1000,
          revokedAt: null,
          favorites: [],
          activities: [],
        };
    if (!existingAccount) addActivity(account, 'account_created', 'Conta criada pelo dono');
    await writeAccounts(existingAccount ? accounts : [...accounts, account]);
    res.status(201).json({ id: account.id, email, name, createdAt: account.createdAt, lastLoginAt: null, expiresAt: account.expiresAt, revokedAt: null });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/access/accounts/:id/activities', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const account = (await readAccounts()).find((candidate) => candidate.id === req.params.id);
    if (!account) {
      res.status(404).json({ error: 'Conta não encontrada.' });
      return;
    }
    res.json({ email: account.email, name: account.name, activities: account.activities });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/admin/access/accounts/:id', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const accounts = await readAccounts();
    const account = accounts.find((candidate) => candidate.id === req.params.id);
    if (!account) {
      res.status(404).json({ error: 'Conta não encontrada.' });
      return;
    }
    account.revokedAt = Date.now();
    await writeAccounts(accounts);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.patch('/api/admin/access/guest-minutes', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const guestMinutes = Number(req.body?.minutes);
    if (!Number.isInteger(guestMinutes) || guestMinutes < 1 || guestMinutes > 1440) {
      res.status(400).json({ error: 'A duração do visitante deve ficar entre 1 e 1440 minutos.' });
      return;
    }
    await writeJsonFile(settingsPath, { guestMinutes });
    res.json({ guestMinutes });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/admin/access/visitors/:id', requireAdmin, requireMaster, async (req, res, next) => {
  try {
    const visitors = await readVisitors();
    const visitor = visitors.find((candidate) => candidate.id === req.params.id);
    if (!visitor) {
      res.status(404).json({ error: 'Acesso de visitante não encontrado.' });
      return;
    }
    visitor.revokedAt = Date.now();
    await writeVisitors(visitors);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get('/api/movies', async (_req, res, next) => {
  try {
    res.json(await readCatalog());
  } catch (error) {
    next(error);
  }
});

app.post('/api/movies', requireAdmin, async (req, res, next) => {
  try {
    const movieData = req.body as Omit<Movie, 'id' | 'createdAt'>;
    if (!movieData?.title?.trim() || !movieData?.video?.trim()) {
      res.status(400).json({ error: 'Título e vídeo são obrigatórios.' });
      return;
    }

    const movie: Movie = { ...movieData, id: Date.now(), createdAt: Date.now() };
    const movies = await readCatalog();
    await writeCatalog([movie, ...movies]);
    res.status(201).json(movie);
  } catch (error) {
    next(error);
  }
});

app.post('/api/movies/upload', requireAdmin, (req, res) => {
  const movieData = req.body?.movieData as Omit<Movie, 'id' | 'createdAt'> | undefined;
  const extension = mediaExtension(String(req.body?.fileName || ''));
  if (!extension) {
    res.status(400).json({ error: 'Formato não suportado. Use MP4, WEBM, MOV, M4V, MKV ou AVI.' });
    return;
  }
  if (!movieData?.title?.trim()) {
    res.status(400).json({ error: 'Título do filme é obrigatório.' });
    return;
  }

  const uploadId = randomUUID();
  pendingUploads.set(uploadId, { movieData, extension });
  setTimeout(() => pendingUploads.delete(uploadId), 30 * 60 * 1000).unref();
  res.status(201).json({ uploadId });
});

app.put('/api/movies/upload/:uploadId', requireAdmin, async (req, res, next) => {
  const pendingUpload = pendingUploads.get(req.params.uploadId);
  if (!pendingUpload) {
    res.status(404).json({ error: 'Envio não encontrado ou expirado. Tente novamente.' });
    return;
  }
  pendingUploads.delete(req.params.uploadId);
  const contentLength = Number(req.header('content-length') || 0);
  if (contentLength > maxVideoBytes) {
    res.status(413).json({ error: 'O vídeo excede o limite de 4 GB.' });
    return;
  }

  const temporaryPath = path.join(mediaDirectory, `${req.params.uploadId}.upload`);
  const finalPath = path.join(mediaDirectory, `${req.params.uploadId}${pendingUpload.extension}`);
  let totalBytes = 0;

  try {
    const sizeLimit = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        totalBytes += chunk.length;
        if (totalBytes > maxVideoBytes) {
          callback(new Error('O vídeo excede o limite de 4 GB.'));
          return;
        }
        callback(null, chunk);
      },
    });

    await pipeline(req, sizeLimit, createWriteStream(temporaryPath, { flags: 'wx' }));
    if (totalBytes === 0) throw new Error('O arquivo de vídeo está vazio.');
    await rename(temporaryPath, finalPath);

    const movie: Movie = {
      ...pendingUpload.movieData,
      video: `/media/${req.params.uploadId}${pendingUpload.extension}`,
      id: Date.now(),
      createdAt: Date.now(),
    };
    const movies = await readCatalog();
    await writeCatalog([movie, ...movies]);
    res.status(201).json(movie);
  } catch (error) {
    await rm(temporaryPath, { force: true });
    await rm(finalPath, { force: true });
    if (error instanceof Error && error.message.includes('4 GB')) {
      res.status(413).json({ error: error.message });
      return;
    }
    next(error);
  }
});

app.delete('/api/movies/:id', requireAdmin, async (req, res, next) => {
  try {
    const movies = await readCatalog();
    const target = movies.find((movie) => movie.id === Number(req.params.id));
    if (!target) {
      res.status(404).json({ error: 'Filme não encontrado.' });
      return;
    }

    const remainingMovies = movies.filter((movie) => movie.id !== target.id);
    await writeCatalog(remainingMovies);
    if (target.video.startsWith('/media/')) {
      await rm(path.join(mediaDirectory, path.basename(target.video)), { force: true });
    }
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.use('/media', express.static(mediaDirectory, { acceptRanges: true, fallthrough: false }));

const isProduction = process.env.NODE_ENV === 'production';
if (isProduction) {
  const distDirectory = path.resolve('dist');
  app.use(express.static(distDirectory));
  app.get('*', (_req, res) => res.sendFile(path.join(distDirectory, 'index.html')));
} else {
  const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
  app.use(vite.middlewares);
}

app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(error);
  if (!res.headersSent) res.status(500).json({ error: 'Falha ao processar a solicitação.' });
});

const httpServer = createHttpServer(app);
httpServer.requestTimeout = 0;
httpServer.listen(port, '0.0.0.0', () => {
  console.log(`CineStream disponível na porta ${port}.`);
});

app.get('/api/public/accounts/:id/session', async (req, res, next) => {
  try {
    const account = (await readAccounts()).find((candidate) => candidate.id === req.params.id);
    if (!account || account.revokedAt || (account.expiresAt !== null && account.expiresAt <= Date.now())) {
      res.status(401).json({ error: 'Esta conta foi expirada ou revogada.' });
      return;
    }
    res.json({ expiresAt: account.expiresAt });
  } catch (error) {
    next(error);
  }
});
