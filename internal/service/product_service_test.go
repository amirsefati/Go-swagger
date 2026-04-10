package service

import (
	"errors"
	"testing"

	"shop-crud/internal/models"
	"shop-crud/internal/repository"
)

type mockProductRepo struct {
	products []models.Product
}

func (m *mockProductRepo) GetAll() ([]models.Product, error) {
	return m.products, nil
}

func (m *mockProductRepo) GetByID(id int) (*models.Product, error) {
	for _, p := range m.products {
		if p.ID == id {
			return &p, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *mockProductRepo) Create(product *models.Product) error {
	product.ID = len(m.products) + 1
	m.products = append(m.products, *product)
	return nil
}

func (m *mockProductRepo) Update(id int, product *models.Product) error {
	for i, p := range m.products {
		if p.ID == id {
			product.ID = id
			m.products[i] = *product
			return nil
		}
	}
	return repository.ErrNotFound
}

func (m *mockProductRepo) Delete(id int) error {
	for i, p := range m.products {
		if p.ID == id {
			m.products = append(m.products[:i], m.products[i+1:]...)
			return nil
		}
	}
	return repository.ErrNotFound
}

func TestGetAllProducts(t *testing.T) {
	repo := &mockProductRepo{
		products: []models.Product{
			{ID: 1, Name: "Apple", Price: 1.5, Stock: 10},
			{ID: 2, Name: "Banana", Price: 0.5, Stock: 20},
		},
	}
	svc := NewProductService(repo)

	products, err := svc.GetAllProducts()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(products) != 2 {
		t.Fatalf("expected 2 products, got %d", len(products))
	}
}

func TestGetProductByID(t *testing.T) {
	repo := &mockProductRepo{
		products: []models.Product{
			{ID: 1, Name: "Apple", Price: 1.5, Stock: 10},
		},
	}
	svc := NewProductService(repo)

	t.Run("existing product", func(t *testing.T) {
		product, err := svc.GetProductByID(1)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if product.Name != "Apple" {
			t.Errorf("expected Apple, got %s", product.Name)
		}
	})

	t.Run("non-existing product", func(t *testing.T) {
		_, err := svc.GetProductByID(999)
		if !errors.Is(err, ErrProductNotFound) {
			t.Errorf("expected ErrProductNotFound, got %v", err)
		}
	})
}

func TestCreateProduct(t *testing.T) {
	repo := &mockProductRepo{products: []models.Product{}}
	svc := NewProductService(repo)

	req := &models.CreateProductRequest{Name: "Orange", Price: 2.0, Stock: 15}
	product, err := svc.CreateProduct(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if product.Name != "Orange" {
		t.Errorf("expected Orange, got %s", product.Name)
	}
	if product.ID == 0 {
		t.Error("expected product ID to be set")
	}
}

func TestUpdateProduct(t *testing.T) {
	repo := &mockProductRepo{
		products: []models.Product{
			{ID: 1, Name: "Apple", Price: 1.5, Stock: 10},
		},
	}
	svc := NewProductService(repo)

	req := &models.UpdateProductRequest{Name: "Green Apple", Price: 2.0, Stock: 5}
	product, err := svc.UpdateProduct(1, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if product.Name != "Green Apple" {
		t.Errorf("expected Green Apple, got %s", product.Name)
	}
}

func TestDeleteProduct(t *testing.T) {
	repo := &mockProductRepo{
		products: []models.Product{
			{ID: 1, Name: "Apple", Price: 1.5, Stock: 10},
		},
	}
	svc := NewProductService(repo)

	err := svc.DeleteProduct(1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	_, err = svc.GetProductByID(1)
	if !errors.Is(err, ErrProductNotFound) {
		t.Errorf("expected ErrProductNotFound after delete, got %v", err)
	}
}
