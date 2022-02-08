<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class OauthController extends Controller
{
    public function redirect(Request $request)
    {
        //-------requerir Permisos-------------------
        $request->session()->put('state', $state = Str::random(40));

        $request->session()->put('code_verifier', $code_verifier = Str::random(128));

        $codeChallenge = strtr(rtrim(
            base64_encode(hash('sha256', $code_verifier, true)),
            '='
        ), '+/', '-_');

        $query = http_build_query([
            'client_id' => config('services.codersfree.client_id'),
            'redirect_uri' => 'http://cliente2.test/callback',
            'response_type' => 'code',
            'scope' => '',
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);
        return redirect('http://api.codersfree.test/oauth/authorize?' . $query);
    }

    public function callback(Request $request)
    {
        //return config('services.codersfree.client_id');
        $state = $request->session()->pull('state');

        $codeVerifier = $request->session()->pull('code_verifier');

        throw_unless(
            strlen($state) > 0 && $state === $request->state,
            InvalidArgumentException::class
        );

        $response = Http::asForm()->post('http://api.codersfree.test/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => config('services.codersfree.client_id'),
            'client_secret' => config('services.codersfree.client_secret'),
            'redirect_uri' => route('callback'),
            'code_verifier' => $codeVerifier,
            'code' => $request->code,
        ]);

        return $response->json();
    }
}
