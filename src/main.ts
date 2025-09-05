import * as yaml from 'js-yaml';
import * as core from '@actions/core';
import * as actionsToolkit from '@docker/actions-toolkit';

import * as context from './context';
import * as docker from './docker';
import * as stateHelper from './state-helper';

interface Auth {
  registry?: string;
  username: string;
  password: string;
  ecr?: string;
}

export async function main(): Promise<void> {
  const inputs: context.Inputs = context.getInputs();
  stateHelper.setLogout(inputs.logout);

  const auths: Array<Auth> = [];
  if (inputs.registry || inputs.username) {
    auths.push({
      registry: inputs.registry,
      username: inputs.username,
      password: inputs.password,
      ecr: inputs.ecr
    });
  }

  const logins = yaml.load(inputs.logins) as Auth[];
  if (Array.isArray(logins)) {
    auths.push(...logins);
  }

  const registries: string[] = [];
  for (const auth of auths) {
    if (!auth.registry) {
      registries.push('docker.io');
    } else {
      registries.push(auth.registry);
    }
  }
  stateHelper.setRegistries(registries.filter((value, index, self) => self.indexOf(value) === index));

  if (auths.length == 0) {
    throw new Error('No registry to login');
  }
  if (auths.length === 1) {
    await docker.login(auths[0].registry || 'docker.io', auths[0].username, auths[0].password, auths[0].ecr || 'auto');
  } else {
    for (const auth of auths) {
      await core.group(`Login to ${auth.registry || 'docker.io'}`, async () => {
        await docker.login(auth.registry || 'docker.io', auth.username, auth.password, auth.ecr || 'auto');
      });
    }
  }
}

async function post(): Promise<void> {
  if (!stateHelper.logout) {
    return;
  }
  for (const registry of stateHelper.registries.split(',')) {
    await docker.logout(registry);
  }
}

actionsToolkit.run(main, post);
