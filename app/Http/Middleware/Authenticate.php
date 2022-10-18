<?php

namespace App\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Support\Facades\Log;

class Authenticate extends Middleware
{
    /**
     * Determine if the user is logged in to any of the given guards.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array  $guards
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    protected function authenticate($request, array $guards)
    {
        if (empty($guards)) {
            // Will retreive the default guard
            $guards = [null];
        }
        else {
            // We replace routes guard by the reverse proxy guard if necessary 
            $proxyGuard = 'reverse-proxy-guard';

            if (config('auth.defaults.guard') === $proxyGuard) {
                $guards = [$proxyGuard];
            }
        }

        foreach ($guards as $guard) {
            Log::debug(sprintf('%s requested', $request->fullUrl()));
            Log::debug(sprintf('laravel_token: %s', $request->cookie('laravel_token')));
            Log::debug(sprintf('XSRF-TOKEN: %s', $request->cookie('XSRF-TOKEN')));
            Log::debug(sprintf('Try to authenticated against %s guard', $guard));
            if ($this->auth->guard($guard)->check()) {
                Log::debug(sprintf('Authenticated against %s guard', $guard));
                $this->auth->shouldUse($guard);
                return;
            }
            Log::debug(sprintf('Fail to authenticate against %s guard', $guard));
        }

        $this->unauthenticated($request, $guards);
    }

}