package cloudonboarding

type FilterData struct {
	Sort   []SortFilter   `json:"sort"`
	Paging PagingFilter   `json:"paging"`
	Filter CriteriaFilter `json:"filter"`
}

type SortFilter struct {
	Field string `json:"FIELD"`
	Order string `json:"ORDER"`
}

type PagingFilter struct {
	From int `json:"from"`
	To   int `json:"to"`
}

type CriteriaFilter struct {
	And []Criteria `json:"AND,omitempty"`
	Or  []Criteria `json:"OR,omitempty"`
}

type Criteria struct {
	SearchField string `json:"SEARCH_FIELD"`
	SearchType  string `json:"SEARCH_TYPE"`
	SearchValue string `json:"SEARCH_VALUE"`
}
