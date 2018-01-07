<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class TokenEntrustAbility extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next, $roles, $permissions, $validateAll = false)
    {
        if (! $token = $this->auth->setRequest($request)->getToken()) {
            return response()->json(['tymon.jwt.absent' => 'token_not_provided'], 400);
        }

        try {
            $user = $this->auth->authenticate($token);
        } catch (TokenExpiredException $e) {
            return response()->json(['tymon.jwt.expired', 'token_expired']);
        } catch (JWTException $e) {
            return response()->json(['tymon.jwt.invalid', 'token_invalid']);
        }

        if (! $user) {
            return response()->json(['tymon.jwt.user_not_found'], 'user_not_found', 404);
        }

        if (!$request->user()->ability(explode('|', $roles), explode('|', $permissions), array('validate_all' => (boolean)$validateAll))) {
            return response()->json(['tymon.jwt.invalid'=> 'token_invalid'], 401);
        }

        // $this->events->fire('tymon.jwt.valid', $user);

        return $next($request);
    }
}
