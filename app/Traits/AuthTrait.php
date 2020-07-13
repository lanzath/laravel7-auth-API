<?php

namespace App\Traits;

use App\Http\Requests\API\Auth\LoginRequest;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Request;

trait AuthTrait
{
    public $credentials;
    public $generatedToken;
    public $user;

    /**
     * Return only email and password.
     *
     * @param  LoginRequest  $request
     * @return array
     */
    protected function getCredentials(LoginRequest $request): array
    {
        return $request->only('email', 'password');
    }

    /**
     * Verify if user is not authorized.
     *
     * @return bool
     */
    protected function isUserNotAuthorized(): bool
    {
        return !Auth::attempt($this->credentials);
    }

    /**
     * Generate user access token.
     *
     * @return object
     */
    protected function handleAuthorization(): object
    {
        return $this->user->createToken('Personal Access Token');
    }

    /**
     * Login user with email and password.
     *
     * @param  LoginRequest  $request
     * @return JsonResponse
     */
    protected function handleLogin(LoginRequest $request): JsonResponse
    {
        $this->credentials = $this->getCredentials($request);

        if ($this->isUserNotAuthorized()) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $this->user = $request->user();

        $this->generatedToken = $this->handleAuthorization();

        if ($request->remember_me) {
            $this->generatedToken->token->expires_at = Carbon::now()->addWeeks(1);
        }

        $this->generatedToken->token->save();

        return response()->json([
            'access_token' => $this->generatedToken->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($this->generatedToken->token->expires_at)->toDateTimeString()
        ]);
    }

    /**
     * Logout user by revoking token
     *
     * @param  Request  $request
     * @return JsonResponse
     */
    protected function handleLogout(Request $request): JsonResponse
    {
        $this->user = $request->user()->token()->revoke();

        return response()->json(['message' => 'Successfully logged out.']);
    }
}
