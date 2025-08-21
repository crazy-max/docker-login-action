import * as core from '@actions/core';
import * as httpm from '@actions/http-client';
import {HttpCodes} from '@actions/http-client';

export interface LoginCredentials {
  username: string;
  token: string;
}

interface OIDCTokenResponse {
  access_token: string;
}

export const isDockerHubOIDC = (registry: string, username: string, password: string): boolean => {
  return username.includes(':') && !password && (registry === '' || registry === 'docker.io' || registry === 'registry-1.docker.io' || registry === 'registry-1-stage.docker.io');
};

export const getOIDCToken = async (registry: string, username: string): Promise<LoginCredentials> => {
  const [user, connectionID] = username.split(':', 2);
  if (!connectionID) {
    throw new Error(`Connection ID is required for Docker Hub OIDC login: ${username}`);
  }

  const idToken = await core.getIDToken('api.docker.com');
  const http: httpm.HttpClient = new httpm.HttpClient('docker-login-action', [], {
    headers: {
      'Content-Type': 'application/json'
    }
  });

  let hubHost = process.env.DOCKERHUB_HOST || 'hub.docker.com';
  if (registry === 'registry-1-stage.docker.io') {
    hubHost = 'hub-stage.docker.com';
  }

  const resp: httpm.HttpClientResponse = await http.post(
    `https://${hubHost}/v2/auth/oidc/token`,
    JSON.stringify({
      connection_id: connectionID,
      token: idToken
    })
  );

  const tokenResp = <OIDCTokenResponse>JSON.parse(await handleResponse(resp));
  core.setSecret(tokenResp.access_token);

  return {
    username: user,
    token: tokenResp.access_token
  };
};

const handleResponse = async (resp: httpm.HttpClientResponse): Promise<string> => {
  const body = await resp.readBody();
  resp.message.statusCode = resp.message.statusCode || HttpCodes.InternalServerError;
  if (resp.message.statusCode < 200 || resp.message.statusCode >= 300) {
    throw parseError(resp, body);
  }
  return body;
};

const parseError = (resp: httpm.HttpClientResponse, body: string): Error => {
  if (resp.message.statusCode == HttpCodes.Unauthorized) {
    throw new Error(`Docker Hub API: operation not permitted`);
  }
  const errResp = <Record<string, string>>JSON.parse(body);
  for (const k of ['message', 'detail', 'error']) {
    if (errResp[k]) {
      throw new Error(`Docker Hub API: bad status code ${resp.message.statusCode}: ${errResp[k]}`);
    }
  }
  throw new Error(`Docker Hub API: bad status code ${resp.message.statusCode}`);
};
