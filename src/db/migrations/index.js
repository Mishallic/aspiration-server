// Migrations run in this order. Add new ones to the end; never edit one that has shipped.
import * as initial from './0001-initial.js';

export const migrations = [{ name: '0001-initial', ...initial }];
