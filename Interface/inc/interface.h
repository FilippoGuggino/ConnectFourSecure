#define ROWS 6
#define COLUMNS 7

enum cell {empty, red, blue};

class Grid{
  private:
    cell grid[ROWS][COLUMNS] = {empty};
  public:
    void printGrid();
    void clear();
    bool setCell(int row, int col, cell color);
};
