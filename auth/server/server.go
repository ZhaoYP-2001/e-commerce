package main

import (
	"context"
	"crypto/rsa"
	"e_commerce/auth/auth"
	"e_commerce/auth/server/token"
	"fmt"
	"google.golang.org/grpc"
	"net"
)

type AuthServer struct {
	auth.UnimplementedAuthServiceServer
}

func (s *AuthServer) DeliverTokenByRPC(ctx context.Context, req *auth.DeliverTokenReq) (*auth.DeliveryResp, error) {

	var prvKey *rsa.PrivateKey
	var err error
	prvKey, err = token.LoadPrvKey(req.UserId)
	if prvKey == nil || err != nil {
		prvKey, err = token.NewPrvKey(req.UserId)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	accessToken, refreshToken, err := token.GenerateToken(req.UserId, prvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &auth.DeliveryResp{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}
func (s *AuthServer) VerifyTokenByRPC(ctx context.Context, req *auth.VerifyTokenReq) (*auth.VerifyResp, error) {

	claims, err := token.GetClaimsFromToken(req.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("unable to get claims from token: %w", err)
	}
	prvKey, err := token.LoadPrvKey(claims.UserId)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	err = token.VerifyAccessToken(&prvKey.PublicKey, req.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	return &auth.VerifyResp{Res: true}, nil
}

func (s *AuthServer) RefreshTokenByRPC(ctx context.Context, req *auth.RefreshTokenReq) (*auth.DeliveryResp, error) {
	claims, err := token.GetClaimsFromToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("unable to get claims from token: %w", err)
	}
	prvKey, err := token.LoadPrvKey(claims.UserId)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	err = token.VerifyRefreshToken(&prvKey.PublicKey, req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify refresh token: %w", err)
	}

	accessToken, refreshToken, err := token.GenerateToken(claims.UserId, prvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &auth.DeliveryResp{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func main() {
	listener, err := net.Listen("tcp", ":8080")
	grpcServer := grpc.NewServer()
	auth.RegisterAuthServiceServer(grpcServer, &AuthServer{})
	if err = grpcServer.Serve(listener); err != nil {
		fmt.Println("failed to serve: %v", err)
	}
}
