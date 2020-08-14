#include "interface.h"
#include <iostream>

using namespace std;

void Grid::printGrid(){

  clear();
  cout<<"stampo grigldsadasdsadsaia"<<endl;
  cout<<"\U0001F534"<<endl;
  cout << "\U0001F535"<<endl;

  for(int k = 0; k < ROWS; k++){
    cout<<endl<<" ";
    for(int i = 0; i < COLUMNS; i++){
      cout<<"\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF ";
    }

    cout<<endl<<"\uFF5C";
    for(int i = 0; i < COLUMNS; i++){
      cout<<"      "<<"\uFF5C";
    }

    cout<<endl<<"\uFF5C";
    for(int i = 0; i < COLUMNS; i++){
      switch(grid[k][i]){
        case empty:
          cout<<"      "<<"\uFF5C";
          break;
        case red:
          cout<<"  \U0001F534  "<<"\uFF5C";
          break;
        case blue:
          cout<<"  \U0001F535  "<<"\uFF5C";
      }
    }

    cout<<endl<<"\uFF5C";
    for(int i = 0; i < COLUMNS; i++){
      cout<<"      "<<"\uFF5C";
    }
  }
  cout<<endl<<" ";
  for(int i = 0; i < COLUMNS; i++){
    cout<<"\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF ";
  }
}

void Grid::clear(){
  #if defined _WIN32
      system("cls");
  #elif defined (__LINUX__) || defined(__gnu_linux__) || defined(__linux__)
      system("clear");
  #elif defined (__APPLE__)
      system("clear");
  #endif
}

bool Grid::setCell(int row, int col, cell color){
  if((row < 0 || row > 5) && (col < 0 || col > 6)) return false;

  //TODO controls

  grid[row][col] = color;

  return true;
}
