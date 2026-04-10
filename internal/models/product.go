package models

import "time"

type Product struct {
	ID        int       `json:"id"`
	Name      string    `json:"name" validate:"required,min=1,max=100"`
	Price     float64   `json:"price" validate:"required,gt=0"`
	Stock     int       `json:"stock" validate:"required,gte=0"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CreateProductRequest struct {
	Name  string  `json:"name" binding:"required,min=1,max=100"`
	Price float64 `json:"price" binding:"required,gt=0"`
	Stock int     `json:"stock" binding:"required,gte=0"`
}

type UpdateProductRequest struct {
	Name  string  `json:"name" binding:"required,min=1,max=100"`
	Price float64 `json:"price" binding:"required,gt=0"`
	Stock int     `json:"stock" binding:"required,gte=0"`
}
