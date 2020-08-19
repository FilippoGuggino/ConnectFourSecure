#include "interface.h"
#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>

using namespace std;

/*****************************

     BaseInterface

******************************/

void BaseInterface::clear(){
  #if defined _WIN32
      system("cls");
  #elif defined (__LINUX__) || defined(__gnu_linux__) || defined(__linux__)
      system("clear");
  #elif defined (__APPLE__)
      system("clear");
  #endif
}


void BaseInterface::printText(){
     clear();

     cout << m_MenuText << endl;
}

/*****************************

     FirstMenu

******************************/

FirstMenu::FirstMenu(vector<string> user_list){
     this->user_list = user_list;
     updateText(user_list);
}

void FirstMenu::updateText(vector<string> user_list){
     m_MenuText = "Users currently online:\n";
     for(int i = 0; i < user_list.size(); i++){
          m_MenuText += to_string(i+1) + ". " + user_list.at(i) + "\n";
     }

     m_MenuText += "Select User Identifier to play against: ";
}

BaseInterface* FirstMenu::getNextMenu(int choice, bool& iIsQuitOptionSelected){
     BaseInterface *aNewMenu = 0; // We're setting up the pointer here, but makin sure it's null (0)

     if(choice > user_list.size() || choice < 1){
          cout<<"Select identifier from 1 to "<<user_list.size()<<endl;
          return this;
     }

     //use name instead of identifier because in the meantime a new user may have connected
     //forgeChallengeRequest(user_list.at(choice));

     /*switch (choice) // Notice - I have only done "options". You would obviously need to do this for all of your menus
     {
          case 2:
          {
               aNewMenu = new SecondMenu; // We're creating our new menu object here, and will send it back to the main function below
          }

          case 3:
          {
               // Ah, they selected quit! Update the bool we got as input
               iIsQuitOptionSelected = true;
          }

          default:
          {
               // Do nothing - we won't change the menu
          }

     }*/

     return new GameInterface;//aNewMenu; // Sending it back to the main function
}

/*****************************

     GameInterface

******************************/


GameInterface::GameInterface(){
     updateGrid();
}

void GameInterface::updateGrid(){

     m_MenuText = "stampo griglia\n";
     //cout<<"\U0001F534"<<endl;
     //cout << "\U0001F535"<<endl;

     for(int k = 0; k < ROWS; k++){
          m_MenuText += "\n ";

          for(int i = 0; i < COLUMNS; i++){
               m_MenuText += "\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF ";
          }

          m_MenuText += "\n\uFF5C";

          for(int i = 0; i < COLUMNS; i++){
               m_MenuText += "      " "\uFF5C";
          }

          m_MenuText += "\n\uFF5C";
          for(int i = 0; i < COLUMNS; i++){
              switch(grid[k][i]){
                case empty:
                  m_MenuText += "      " "\uFF5C";
                  break;
                case red:
                  m_MenuText += "  \U0001F534  " "\uFF5C";
                  break;
                case blue:
                  m_MenuText += "  \U0001F535  " "\uFF5C";
              }
            }

            m_MenuText += "\n\uFF5C";
            for(int i = 0; i < COLUMNS; i++){
              m_MenuText += "      " "\uFF5C";
            }
       }
       m_MenuText += "\n ";

       for(int i = 0; i < COLUMNS; i++){
            m_MenuText += "\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF\u23AF ";
       }

       m_MenuText += "\n" "    ";
       for(int i = 0; i < COLUMNS; i++){
            m_MenuText += to_string(i+1) + "       ";
       }

       m_MenuText += "\n\nChoose column where to put the token: ";

       /*cout<<"stampo griglia"<<endl;
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
     }*/


}

BaseInterface* GameInterface::getNextMenu(int col, bool& iIsQuitOptionSelected){
     setCell(col, red);
     return this;
}

//TODO controls for color
bool GameInterface::setCell(int col, cell color){
     col = col - 1;
     cout<<"col: "<<col<<endl;
       //check for out of bound input
       if(col < 0 || col > 6) return false;

       //TODO controls
       for(int i = 5; i >= 0; i--){
            if(grid[i][col] == empty){
                 grid[i][col] = color;
                 updateGrid();
                 if(checkWinCondition(i, col))
                    cout<<"HAI VINTO!";
                 else
                    cout<<"HAI PERSO!";
                 return true;
            }
      }

     cout<<"column is full"<<endl;

      //it means the adversary selected an already full column, since this case is already checked by the client
      //it means the adversary is trying to cheat
      //closeMatch();
      return false;
}

bool GameInterface::checkWinCondition(int row, int col){
     int vertical = 1;//(|)
	int horizontal = 1;//(-)
	int diagonal1 = 1;//(\)
	int diagonal2 = 1;//(/)
	int i;//vertical
	int ii;//horizontal

	//check for vertical(|)
	for(i = row +1;grid[i][col] == red && i <= 5;i++,vertical++);//Check down
	for(i = row -1;grid[i][col] == red && i >= 0;i--,vertical++);//Check up
	if(vertical >= 4)return true;
	//check for horizontal(-)
	for(ii = col -1;grid[row][ii] == red && ii >= 0;ii--,horizontal++);//Check left
	for(ii = col +1;grid[row][ii] == red && ii <= 6;ii++,horizontal++);//Check right
	if(horizontal >= 4) return true;
	//check for diagonal 1 (\)
	for(i = row -1, ii= col -1;grid[i][ii] == red && i>=0 && ii >=0; diagonal1 ++, i --, ii --);//up and left
	for(i = row +1, ii = col+1;grid[i][ii] == red && i<=5 && ii <=6;diagonal1 ++, i ++, ii ++);//down and right
	if(diagonal1 >= 4) return true;
	//check for diagonal 2(/)
	for(i = row -1, ii= col +1;grid[i][ii] == red && i>=0 && ii <= 6; diagonal2 ++, i --, ii ++);//up and right
	for(i = row +1, ii= col -1;grid[i][ii] == red && i<=5 && ii >=0; diagonal2 ++, i ++, ii --);//up and left
	if(diagonal2 >= 4) return true;

	return false;
}
