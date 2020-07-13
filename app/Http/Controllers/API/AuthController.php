<?php

namespace App\Http\Controllers\API;

use App\User;
use App\Http\Controllers\Controller;
use App\Http\Requests\API\Auth\LoginRequest;
use App\Http\Requests\API\Auth\SignupRequest;
use App\Traits\AuthTrait;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    use AuthTrait;

    /**
     * Create a new User
     *
     * @param  SignupRequest $request
     * @return JsonResponse
     */
    public function signup(SignupRequest $request): JsonResponse
    {
        return response()->json(User::create($request->validated()), 201);
    }

    /**
     * Login user and create token
     *
     * @param  LoginRequest $request
     * @return JsonResponse
     */
    public function login(LoginRequest $request): JsonResponse
    {
        return $this->handleLogin($request);
    }

    /**
     * Logout User (Revoke the token)
     *
     * @param  Request $request
     * @return JsonResponse
     */
    public function logout(Request $request): JsonResponse
    {
        $request->user()->token()->revoke();

        return response()->json(['message' => 'Successfully logged out.']);
    }

    /**
     * Get the authenticated user
     *
     * @param  Request $request
     * @return JsonResponse
     */
    public function user(Request $request): JsonResponse
    {
        return response()->json($request->user());
    }
}
