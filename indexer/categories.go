package indexer

// TorznabCategory represents a standard category.
type TorznabCategory struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// StandardCategories is a map of all standard Torznab categories.
var StandardCategories = map[int]TorznabCategory{
	1000: {ID: 1000, Name: "Console", Description: "Games for consoles"},
	2000: {ID: 2000, Name: "Movies", Description: "All movies"},
	2010: {ID: 2010, Name: "Movies/Foreign", Description: "Foreign language movies"},
	2020: {ID: 2020, Name: "Movies/Other", Description: "Other movies"},
	2030: {ID: 2030, Name: "Movies/SD", Description: "Standard definition movies"},
	2040: {ID: 2040, Name: "Movies/HD", Description: "High definition movies"},
	2050: {ID: 2050, Name: "Movies/UHD", Description: "Ultra high definition movies"},
	2060: {ID: 2060, Name: "Movies/3D", Description: "3D movies"},
	2070: {ID: 2070, Name: "Movies/BluRay", Description: "Full BluRay discs"},
	2080: {ID: 2080, Name: "Movies/DVD", Description: "Full DVD discs"},
	3000: {ID: 3000, Name: "Audio", Description: "All audio"},
	3010: {ID: 3010, Name: "Audio/MP3", Description: "MP3 audio"},
	3020: {ID: 3020, Name: "Audio/Video", Description: "Music videos"},
	3030: {ID: 3030, Name: "Audio/Audiobook", Description: "Audiobooks"},
	3040: {ID: 3040, Name: "Audio/Lossless", Description: "Lossless audio formats"},
	4000: {ID: 4000, Name: "PC", Description: "PC software and games"},
	4010: {ID: 4010, Name: "PC/0day", Description: "0day software"},
	4020: {ID: 4020, Name: "PC/ISO", Description: "ISO images"},
	4030: {ID: 4030, Name: "PC/Mac", Description: "Mac software"},
	4040: {ID: 4040, Name: "PC/Mobile-Other", Description: "Mobile software (other)"},
	4050: {ID: 4050, Name: "PC/Games", Description: "PC games"},
	4060: {ID: 4060, Name: "PC/Mobile-iOS", Description: "iOS software"},
	4070: {ID: 4070, Name: "PC/Mobile-Android", Description: "Android software"},
	5000: {ID: 5000, Name: "TV", Description: "All TV shows"},
	5010: {ID: 5010, Name: "TV/WEB-DL", Description: "TV shows from web sources"},
	5020: {ID: 5020, Name: "TV/Foreign", Description: "Foreign language TV shows"},
	5030: {ID: 5030, Name: "TV/SD", Description: "Standard definition TV shows"},
	5040: {ID: 5040, Name: "TV/HD", Description: "High definition TV shows"},
	5050: {ID: 5050, Name: "TV/UHD", Description: "Ultra high definition TV shows"},
	5060: {ID: 5060, Name: "TV/Other", Description: "Other TV shows"},
	5070: {ID: 5070, Name: "TV/Sport", Description: "Sport events"},
	5080: {ID: 5080, Name: "TV/Anime", Description: "Anime"},
	6000: {ID: 6000, Name: "XXX", Description: "Adult content"},
	6010: {ID: 6010, Name: "XXX/DVD", Description: "Adult DVDs"},
	6020: {ID: 6020, Name: "XXX/WMV", Description: "Adult WMV"},
	6030: {ID: 6030, Name: "XXX/XviD", Description: "Adult XviD"},
	6040: {ID: 6040, Name: "XXX/x264", Description: "Adult x264"},
	6050: {ID: 6050, Name: "XXX/Pack", Description: "Adult packs"},
	6060: {ID: 6060, Name: "XXX/ImgSet", Description: "Adult image sets"},
	6070: {ID: 6070, Name: "XXX/Other", Description: "Other adult content"},
	7000: {ID: 7000, Name: "Books", Description: "All books"},
	7010: {ID: 7010, Name: "Books/Mags", Description: "Magazines"},
	7020: {ID: 7020, Name: "Books/Ebook", Description: "E-books"},
	7030: {ID: 7030, Name: "Books/Comics", Description: "Comics"},
	8000: {ID: 8000, Name: "Other", Description: "Other content"},
}

// GetStandardCategories returns a slice of all standard categories, sorted by name.
func GetStandardCategories() []TorznabCategory {
	// This function is not implemented in this snippet,
	// but it would return a sorted slice of the values from the map above.
	// We'll use the map directly for simplicity.
	return nil
}
