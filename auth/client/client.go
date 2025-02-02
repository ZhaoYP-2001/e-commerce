package main

import (
	"context"
	"e_commerce/auth/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	client := auth.NewAuthServiceClient(conn)
	ctx := context.Background()
	userId := "user-id"
	deliveryResp, err := client.DeliverTokenByRPC(ctx, &auth.DeliverTokenReq{UserId: userId})
	if err != nil {
		panic(err)
	}
	verifyResp, err := client.VerifyTokenByRPC(ctx, &auth.VerifyTokenReq{AccessToken: deliveryResp.AccessToken})
	if err != nil {
		panic(err)
	}
	if !verifyResp.Res {
		panic("verify fail")
	}
	refreshResp, err := client.RefreshTokenByRPC(ctx, &auth.RefreshTokenReq{RefreshToken: deliveryResp.RefreshToken})
	if err != nil {
		panic(err)
	}
	verifyResp, err = client.VerifyTokenByRPC(ctx, &auth.VerifyTokenReq{AccessToken: refreshResp.AccessToken})
	if err != nil {
		panic(err)
	}
	if !verifyResp.Res {
		panic("verify fail")
	}

}
